#ifndef ALGO_H
#define ALGO_H
#include "Util.hpp"
#include <unordered_map>
#include <unordered_set>

using namespace SVF;
using namespace std;
using namespace llvm;

class PNwithOffset {
public:
  s64_t offset;
  bool curFlow;
  PNwithOffset(s64_t os, bool cf) : offset(os), curFlow(cf) {}
};

class Algo {
public:
  unordered_set<PAGEdge *> visitedEdges;
  stack<PNwithOffset*> HistoryAwareStack;
  map<s64_t, unordered_set<PAGNode *>> Aliases;
  SVFIR *pag;
  bool taken = false;
  PAGNode *taskNode;
  unordered_set<NodeID> BlockedNodes;
  unordered_set<PAGNode *> visitedicalls;
  unordered_map<PAGNode *, u64_t> nodeFreq;
  unordered_set<const Function *> depFuncs;
  unordered_set<CallInst *> depiCalls;
  int counter = 0;

  bool ifValidForTypebasedShortcut(PAGEdge *edge, u32_t threshold);

  bool ifValidForCastSiteShortcut(PAGEdge *edge, u32_t threshold);

  void Prop(PAGNode *nxt, PAGEdge *eg, bool state, PAGNode *icall);

  void ComputeAlias(PAGNode *cur, bool state);
};

#endif