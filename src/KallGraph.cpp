#include "SVF-FE/SVFIRBuilder.h"
#include "WPA/Andersen.h"
#include "llvm/Bitcode/BitcodeWriter.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/Verifier.h"
#include "llvm/Support/PrettyStackTrace.h"
#include "llvm/Support/Signals.h"
#include "llvm/Support/SourceMgr.h"
#include "llvm/Support/SystemUtils.h"

#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <string>
#include <sys/resource.h>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <condition_variable>

#include "include/KallGraphAlgo.hpp"
#include "include/Util.hpp"

using namespace llvm;
using namespace SVF;

// Command line parameters.
cl::list<std::string> InputFilenames(cl::Positional, cl::OneOrMore,
                                     cl::desc("<input bitcode files>"));

cl::opt<unsigned>
    VerboseLevel("verbose-level",
                 cl::desc("Print information at which verbose level"),
                 cl::init(0));

static llvm::cl::opt<std::string>
    OutputDir("OutputDir", llvm::cl::desc("OutputDir"), llvm::cl::init(""));

static llvm::cl::opt<std::string> CallGraphPath("CallGraphPath",
                                                llvm::cl::desc("CallGraphPath"),
                                                llvm::cl::init(""));

static llvm::cl::opt<size_t> ThreadNum("ThreadNum", llvm::cl::desc("ThreadNum"),
                                       llvm::cl::init(1));

struct LocalMaps {
  unordered_map<const CallInst *, unordered_set<const Function *>>
      localcallgraph;
  unordered_map<const Function *, unordered_set<CallInst *>> localDepFuncs;
  unordered_map<CallInst *, unordered_set<CallInst *>> localDepiCalls;
  unordered_set<const Function *> localnewtargets;
  unordered_set<CallInst *> localnewicalls;
};

struct TaskContext {
  CallInst *icall;
  LocalMaps &local;
};

void createOutputFolder() {
  if (OutputDir.empty()) {
    perror("Please specify -OutputDir=/path/to/your/output/folder !\n");
    exit(1);
  }
  auto now = std::chrono::system_clock::now();
  std::time_t now_time = std::chrono::system_clock::to_time_t(now);
  std::ostringstream oss;
  oss << std::put_time(std::localtime(&now_time), "%Y%m%d_%H%M%S");
  std::filesystem::path outputPath =
      std::filesystem::path(OutputDir.getValue()) / oss.str();
  try {
    std::filesystem::create_directories(outputPath);
    std::cout << "Created output folder: " << outputPath << std::endl;
  } catch (const std::filesystem::filesystem_error &e) {
    std::cerr << "Error creating folder: " << e.what() << std::endl;
  }
  OutputDir = outputPath.string();
}

unordered_set<CallInst *> callinsts;
void getAllicalls(SVFModule *M) {
  for (auto func : *M) {
    for (auto &bb : *(func->getLLVMFun())) {
      for (auto &inst : bb) {
        if (auto callins = dyn_cast<CallInst>(&inst)) {
          if (callins->isIndirectCall()) {
            callinsts.insert(callins);
          }
        }
      }
    }
  }
}

set<const CallInst *> *getiCallOperands(string filename) {
  auto ops = new set<const CallInst *>();
  for (auto callinst : callinsts) {
    if (auto dbginfo = callinst->getDebugLoc()) {
      if ((dbginfo->getFilename().str() + ":" +
           to_string(dbginfo->getLine())) == filename) {
        ops->insert(callinst);
      }
    }
  }
  return ops;
}

void processTraces(SVFIR *pag) {
  if (typebasedShortcuts.find("struct.tracepoint_func") !=
      typebasedShortcuts.end()) {
    for (auto edge : typebasedShortcuts["struct.tracepoint_func"][0]) {
      for (auto loadout : edge->getDstNode()->getOutgoingEdges(PAGEdge::Load)) {
        for (auto copyout :
             loadout->getDstNode()->getOutgoingEdges(PAGEdge::Copy)) {
          traceNodes.insert(copyout->getDstID());
        }
      }
    }
    for (auto icall : callinsts) {
      if (traceNodes.find(pag->getValueNode(icall->getCalledOperand())) !=
          traceNodes.end()) {
        traceiCalls.insert(icall);
      }
    }
  }
}

void processTraceIcalls(const CallInst *icall, LocalMaps &maps) {
  if (type2funcs.find(printType(icall->getCalledOperand()->getType())) !=
      type2funcs.end()) {
    for (auto func :
         type2funcs[printType(icall->getCalledOperand()->getType())]) {
      maps.localcallgraph[icall].insert(func);
    }
  }
}

void processSELinuxhooks(SVFIR *pag, SVFModule *svfmod) {
  GlobalVariable *selinuxhooks = nullptr;
  for (auto ii = svfmod->global_begin(), ie = svfmod->global_end(); ii != ie;
       ii++) {
    if ((*ii)->getName().str() == "selinux_hooks") {
      selinuxhooks = *ii;
    }
  }
  if (selinuxhooks == nullptr) {
    return;
  }
  for (auto edge : typebasedShortcuts["struct.security_hook_list"][24]) {
    for (auto castout : edge->getDstNode()->getOutgoingEdges(PAGEdge::Copy)) {
      for (auto loadout :
           castout->getDstNode()->getOutgoingEdges(PAGEdge::Load)) {
        SELinuxNodes.insert(loadout->getDstID());
      }
    }
  }
  for (auto icall : callinsts) {
    if (SELinuxNodes.find(pag->getValueNode(icall->getCalledOperand())) !=
        SELinuxNodes.end()) {
      SELinuxicalls.insert(icall);
    }
  }
  for (auto edge : pag->getGNode(pag->getValueNode(selinuxhooks))
                       ->getOutgoingEdges(PAGEdge::Gep)) {
    for (auto storein : edge->getDstNode()->getIncomingEdges(PAGEdge::Store)) {
      if (storein->getSrcNode()->hasValue() &&
          isa<Function>(storein->getSrcNode()->getValue())) {
        SELinuxfuncs.insert(
            dyn_cast<Function>(storein->getSrcNode()->getValue()));
      }
    }
  }
}

void processSELinuxIcalls(const CallInst *icall, LocalMaps &maps) {
  if (type2funcs.find(printType(icall->getCalledOperand()->getType())) !=
      type2funcs.end()) {
    for (auto func :
         type2funcs[printType(icall->getCalledOperand()->getType())]) {
      if (SELinuxfuncs.find(func) != SELinuxfuncs.end()) {
        maps.localcallgraph[icall].insert(func);
      }
    }
  }
}

unordered_set<CallInst *> *getSpecifyInput(SVFModule *svfmod) {
  if (SpecifyInput == "") {
    return nullptr;
  }
  unordered_set<string> icalls;
  unordered_set<string> found_icalls;
  string tmp;
  ifstream fin(SpecifyInput);
  while (!fin.eof()) {
    fin >> tmp;
    icalls.insert(tmp);
  }
  auto ret = new unordered_set<CallInst *>();
  for (auto func : *svfmod) {
    for (auto &bb : *(func->getLLVMFun())) {
      for (auto &inst : bb) {
        if (auto icall = dyn_cast<CallInst>(&inst)) {
          if (icall->isIndirectCall()) {
            if (auto dbginfo = icall->getDebugLoc()) {
              auto path = dbginfo->getFilename().str() + ":" +
                          to_string(dbginfo->getLine());
              if (icalls.find(path) != icalls.end()) {
                ret->insert(icall);
                found_icalls.insert(path);
              }
            }
          }
        }
      }
    }
  }
  for (auto icall : icalls) {
    if (found_icalls.find(icall) == found_icalls.end()) {
      errs() << icall << " not found\n";
    }
  }
  return ret;
}

Algo *performAnalysis(Value *gv, SVFIR *pag) {
  auto *unias = new Algo();
  unias->pag = pag;
  for (auto node : BlockedNodes) {
    unias->BlockedNodes.insert(node);
  }
  PNwithOffset firstLayer(0, true);
  unias->HistoryAwareStack.push(firstLayer);
  auto pgnode = pag->getGNode(pag->getValueNode(gv));
  unias->taskNode = pgnode;
  unias->ComputeAlias(pgnode, true);
  return unias;
}

void eachThread(SVFIR *pag, TaskContext &task) {
  string path;
  auto icall = task.icall;
  if (auto dbginfo = icall->getDebugLoc()) {
    path = dbginfo->getFilename().str() + ":" + to_string(dbginfo->getLine());
  }
  cout << pag->getValueNode(icall->getCalledOperand()->stripPointerCasts())
       << " " << path << "\n";
  if (traceiCalls.find(icall) != traceiCalls.end()) {
    processTraceIcalls(icall, task.local);
  } else if (SELinuxicalls.find(icall) != SELinuxicalls.end()) {
    processSELinuxIcalls(icall, task.local);
  } else {
    auto res =
        performAnalysis(icall->getCalledOperand()->stripPointerCasts(), pag);
    for (auto alias : res->Aliases[0]) {
      if (alias->hasValue()) {
        if (auto func = dyn_cast<Function>(alias->getValue())) {
          if (alias->getId() == pag->getValueNode(func) &&
              icall->arg_size() == func->arg_size()) {
            if (checkIfMatch(icall, func)) {
              if (task.local.localcallgraph.find(icall) ==
                  task.local.localcallgraph.end()) {
                task.local.localnewicalls.insert(icall);
              } else if (task.local.localcallgraph[icall].find(func) ==
                         task.local.localcallgraph[icall].end()) {
                task.local.localnewtargets.insert(func);
              }
              task.local.localcallgraph[icall].insert(func);
            }
          }
        }
      }
    }
    for (auto func : res->depFuncs) {
      task.local.localDepFuncs[func].insert(icall);
    }
    for (auto iicall : res->depiCalls) {
      task.local.localDepiCalls[iicall].insert(icall);
    }
    delete res;
  }
}

size_t getCallGraphSizeSum() {
  size_t total = 0;
  for (const auto &pair : callgraph) {
    total += pair.second.size();
  }
  return total;
}

class ThreadPool {
public:
  ThreadPool(size_t thread_count, SVFIR *pag, std::deque<CallInst *> &tasks)
      : pag_(pag), tasks_(tasks), stop_(false), thread_data_(thread_count) {
    for (size_t i = 0; i < thread_count; ++i) {
      workers_.emplace_back(&ThreadPool::worker_thread, this, i);
    }
  }

  ~ThreadPool() {
    {
      std::unique_lock<std::mutex> lock(mutex_);
      stop_ = true;
      cond_var_.notify_all();
    }
    for (std::thread &worker : workers_) {
      if (worker.joinable()) {
        worker.join();
      }
    }
    for (auto &data : thread_data_) {
      for (auto &p : data.localcallgraph)
        callgraph[p.first].insert(p.second.begin(), p.second.end());
      for (auto &p : data.localDepFuncs)
        GlobalDepFuncs[p.first].insert(p.second.begin(), p.second.end());
      for (auto &p : data.localDepiCalls)
        GlobalDepiCalls[p.first].insert(p.second.begin(), p.second.end());
      newiCalls.insert(data.localnewicalls.begin(), data.localnewicalls.end());
      newTargets.insert(data.localnewtargets.begin(),
                        data.localnewtargets.end());
    }
  }

private:
  void worker_thread(size_t index) {
    static int t = 0;
    while (true) {
      CallInst *icall = nullptr;
      {
        std::unique_lock<std::mutex> lock(mutex_);
        cond_var_.wait(lock, [this]() { return stop_ || !tasks_.empty(); });
        if (stop_ && tasks_.empty()) {
          return;
        }
        icall = tasks_.front();
        tasks_.pop_front();
      }
      TaskContext ctx{icall, thread_data_[index]};
      eachThread(pag_, ctx);
    }
  }

  std::vector<std::thread> workers_;
  std::deque<CallInst *> &tasks_;
  std::mutex mutex_;
  std::condition_variable cond_var_;
  std::atomic<bool> stop_;
  std::vector<LocalMaps> thread_data_;
  SVFIR *pag_;
};

void analysis(SVFModule *M, SVFIR *pag, std::deque<CallInst *> &tasks) {
  errs() << "task size: " << tasks.size() << "\n";
  ThreadPool pool(ThreadNum, pag, tasks);
}

void initialize(SVFIR *pag, SVFModule *svfModule) {
  getBlockedNodes(pag);
  setupPhiEdges(pag);
  setupSelectEdges(pag);
  handleAnonymousStruct(svfModule, pag);
  addSVFAddrFuncs(svfModule, pag);
  collectByteoffset(pag);
  setupStores(pag);
  processCastSites(pag, svfModule);
  setupDependence(pag, svfModule);
  getAllicalls(svfModule);
  processTraces(pag);
  processSELinuxhooks(pag, svfModule);
  processCastMap(pag);
  errs() << "shortcuts setup! " << "\n";
}

unordered_map<u32_t, unordered_map<string, unordered_set<u32_t>>> sizeMaps;

void sortSizeMap(
    std::vector<pair<u32_t, unordered_map<string, unordered_set<u32_t>>>>
        &sorted,
    unordered_map<u32_t, unordered_map<string, unordered_set<u32_t>>> &before) {
  sorted.reserve(before.size());
  for (const auto &kv : before) {
    sorted.emplace_back(kv.first, kv.second);
  }
  std::stable_sort(
      std::begin(sorted), std::end(sorted),
      [](const pair<u32_t, unordered_map<string, unordered_set<u32_t>>> &a,
         const pair<u32_t, unordered_map<string, unordered_set<u32_t>>> &b) {
        return a.first > b.first;
      });
}

void checkShortcuts() {
  ofstream fout(OutputDir + "/stats");
  for (auto st : typebasedShortcuts) {
    for (auto idx : st.second) {
      sizeMaps[idx.second.size()][st.first].insert(idx.first);
    }
  }
  std::vector<pair<u32_t, unordered_map<string, unordered_set<u32_t>>>> sorted;
  sortSizeMap(sorted, sizeMaps);
  for (auto elem : sorted) {
    fout << elem.first << "\n";
    for (auto st : elem.second) {
      for (auto fd : st.second) {
        fout << st.first << "\t" << fd << "\n";
      }
    }
    fout << "\n\n\n";
  }
  fout.close();
}

auto program_start = std::chrono::steady_clock::now();

void log_time(const std::string &stage_name, ofstream &fout) {
  auto now = std::chrono::steady_clock::now();
  auto elapsed = std::chrono::duration<double>(now - program_start).count();
  fout << "[" << stage_name << "] Time since start: " << elapsed << "s"
       << std::endl;
}

void printCallGraph(string filename) {
  ofstream fout(filename);
  for (auto icall : callgraph) {
    auto dbginfo = icall.first->getDebugLoc();
    string output = dbginfo->getFilename().str() + ":" +
                    to_string(dbginfo->getLine()) + "\n" +
                    to_string(icall.second.size()) + "\n";
    for (auto func : icall.second) {
      output += func->getName().str() + "\n";
    }
    fout << output << endl;
    fout << endl << flush;
  }
}

int main(int argc, char **argv) {
  int arg_num = 0;
  char **arg_value = new char *[argc];
  std::vector<std::string> moduleNameVec;
  processArguments(argc, argv, arg_num, arg_value, moduleNameVec);
  cl::ParseCommandLineOptions(arg_num, arg_value,
                              "Whole Program Points-to Analysis\n");
  delete[] arg_value;
  createOutputFolder();

  SVFModule *svfModule =
      LLVMModuleSet::getLLVMModuleSet()->buildSVFModule(moduleNameVec);
  svfModule->buildSymbolTableInfo();

  ofstream fout(OutputDir + "/log");
  SVFIRBuilder builder;
  SVFIR *pag = builder.build(svfModule);
  errs() << "pag built!\n";
  log_time("pag built", fout);
  baseNum = (moduleNameVec.size() > THRESHOLD) ? ALLYESCONFIG : DEFCONFIG;
  initialize(pag, svfModule);

  std::deque<CallInst *> tasks;
  if (auto input = getSpecifyInput(svfModule)) {
    tasks = std::deque<CallInst *>(input->begin(), input->end());
  } else {
    tasks = std::deque<CallInst *>(callinsts.begin(), callinsts.end());
  }
  log_time("starting round 0", fout);
  analysis(svfModule, pag, tasks);
  size_t new_callgraph_size = getCallGraphSizeSum();
  while (SpecifyInput == "" && new_callgraph_size != callgraph_size) {
    static int i = 1;
    printCallGraph(OutputDir + "/callgraph" + to_string(i));
    log_time("starting round " + to_string(i++), fout);
    fout << "new callgraph size: " << new_callgraph_size << "\n";
    callgraph_size = new_callgraph_size;
    setupCallGraph(pag);
    unordered_set<CallInst *> task_set;
    for (auto new_func : newTargets) {
      for (auto nxt_task : GlobalDepFuncs[new_func]) {
        if (fixediCalls.find(nxt_task) == fixediCalls.end()) {
          fixediCalls.insert(nxt_task);
          task_set.insert(nxt_task);
        }
      }
    }
    newTargets.clear();
    for (auto new_icall : newiCalls) {
      for (auto nxt_task : GlobalDepiCalls[new_icall]) {
        if (fixediCalls.find(nxt_task) == fixediCalls.end()) {
          fixediCalls.insert(nxt_task);
          task_set.insert(nxt_task);
        }
      }
    }
    newiCalls.clear();
    for (auto task : task_set) {
      tasks.push_back(task);
    }
    fout << "new task size: " << tasks.size() << "\n";
    fout.flush();
    analysis(svfModule, pag, tasks);
    new_callgraph_size = getCallGraphSizeSum();
  }
  log_time("analysis done", fout);
  fout.close();
  return 0;
}
