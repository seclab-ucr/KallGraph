#include "../include/KallGraphAlgo.hpp"

bool Algo::ifValidForTypebasedShortcut(PAGEdge *edge, u32_t threshold) {
  if (edge->getSrcNode()->getType()) {
    if (auto sttype = ifPointToStruct(edge->getSrcNode()->getType())) {
      auto offset = gep2byteoffset[edge];
      if (typebasedShortcuts.find(getStructName(sttype)) !=
              typebasedShortcuts.end() &&
          typebasedShortcuts[getStructName(sttype)].find(offset) !=
              typebasedShortcuts[getStructName(sttype)].end() &&
          typebasedShortcuts[getStructName(sttype)][offset].size() <
              threshold) {
        return true;
      }
    }
  }
  return false;
}

bool Algo::ifValidForCastSiteShortcut(PAGEdge *edge, u32_t threshold) {
  if (edge->getSrcNode()->getType()) {
    if (auto sttype = ifPointToStruct(edge->getSrcNode()->getType())) {
      if (castSites[getStructName(sttype)].size() < threshold) {
        return true;
      }
    }
  }
  return false;
}

void Algo::Prop(PAGNode *nxt, PAGEdge *eg, bool state, PAGNode *icall) {
  if (BlockedNodes.find(nxt->getId()) != BlockedNodes.end()) {
    return;
  }
  if (visitedEdges.size() > 35) {
    return;
  }
  if (eg && !visitedEdges.insert(eg).second) {
    return;
  }
  if (icall && !visitedicalls.insert(icall).second) {
    return;
  }
  ComputeAlias(nxt, state);
  if (icall) {
    visitedicalls.erase(icall);
  }
  if (eg) {
    visitedEdges.erase(eg);
  }
}

static inline bool isMemAllocFunction(const StringRef &name) {
  return name.find("kmalloc") != string::npos ||
         name.find("kzalloc") != string::npos ||
         name.find("kcalloc") != string::npos;
}

void Algo::ComputeAlias(PAGNode *cur, bool state) {
  if (visitedEdges.size() > 15) {
    nodeFreq[cur]++;
    counter++;
  }
  auto param_it = Param2Funcs.find(cur->getId());
  if (param_it != Param2Funcs.end()) {
    depFuncs.insert(param_it->second);
  }
  auto arg_it = Arg2iCalls.find(cur->getId());
  if (arg_it != Arg2iCalls.end()) {
    depiCalls.insert(arg_it->second);
  }
  if (counter > 20000) {
    vector<pair<PAGNode *, u64_t>> nodeFreqSorted;
    sortMap(nodeFreqSorted, nodeFreq, 50);
    for (auto i = 0; i < 50 && i < nodeFreqSorted.size(); i++) {
      BlockedNodes.insert(nodeFreqSorted[i].first->getId());
    }

    nodeFreq.clear();
    counter = 0;
  }

  if (HistoryAwareStack.size() == 1) {
    Aliases[HistoryAwareStack.top()->offset].insert(cur);
  }

  if (cur->hasOutgoingEdges(PAGEdge::Load)) {
    for (auto edge : cur->getOutgoingEdges(PAGEdge::Load)) {
      if (HistoryAwareStack.size() > 1) {
        auto topItem = HistoryAwareStack.top();
        if (topItem->offset == 0) {
          HistoryAwareStack.pop();
          Prop(edge->getDstNode(), edge, false, nullptr);
          HistoryAwareStack.push(topItem);
        }
      }
    }
  }

  if (HistoryAwareStack.size() > 1) {
    auto topItem = HistoryAwareStack.top();
    if (topItem->curFlow && topItem->offset == 0 &&
        cur->hasIncomingEdges(PAGEdge::Store)) {
      for (auto edge : cur->getIncomingEdges(PAGEdge::Store)) {
        HistoryAwareStack.pop();
        Prop(edge->getSrcNode(), edge, true, nullptr);
        HistoryAwareStack.push(topItem);
      }
    }
  }

  if (HistoryAwareStack.size() > 1) {
    if (cur->hasOutgoingEdges(PAGEdge::Copy)) {
      for (auto edge : cur->getOutgoingEdges(PAGEdge::Copy)) {
        Prop(edge->getDstNode(), edge, false, nullptr);
      }
    }

    if (selectOut.find(cur->getId()) != selectOut.end()) {
      for (auto edge : selectOut[cur->getId()]) {
        for (auto dst : edge.second) {
          Prop(pag->getGNode(dst), edge.first, false, nullptr);
        }
      }
    }
    if (phiOut.find(cur->getId()) != phiOut.end()) {
      for (auto edge : phiOut[cur->getId()]) {
        for (auto dst : edge.second) {
          Prop(pag->getGNode(dst), edge.first, false, nullptr);
        }
      }
    }
    if (Real2Formal.find(cur->getId()) != Real2Formal.end()) {
      for (auto formal : Real2Formal[cur->getId()]) {
        Prop(pag->getGNode(formal), nullptr, false, cur);
      }
    }
    if (cur->hasOutgoingEdges(PAGEdge::Call)) {
      for (auto edge : cur->getOutgoingEdges(PAGEdge::Call)) {
        auto callee = SVFUtil::getCallee(
            dyn_cast<CallPE>(edge)->getCallInst()->getCallSite());
        if (callee && isMemAllocFunction(callee->getName())) {
          continue;
        }
        Prop(edge->getDstNode(), edge, false, nullptr);
      }
    }

    if (Ret2Call.find(cur->getId()) != Ret2Call.end()) {
      for (auto callsite : Ret2Call[cur->getId()]) {
        Prop(pag->getGNode(callsite), nullptr, false, pag->getGNode(callsite));
      }
    }
    if (cur->hasOutgoingEdges(PAGEdge::Ret)) {
      for (auto edge : cur->getOutgoingEdges(PAGEdge::Ret)) {
        auto callee = SVFUtil::getCallee(
            dyn_cast<RetPE>(edge)->getCallInst()->getCallSite());
        if (callee && isMemAllocFunction(callee->getName())) {
          continue;
        }
        Prop(edge->getDstNode(), edge, false, nullptr);
      }
    }
  }

  if (state) {
    if (cur->hasIncomingEdges(PAGEdge::Copy)) {
      for (auto edge : cur->getIncomingEdges(PAGEdge::Copy)) {
        Prop(edge->getSrcNode(), edge, true, nullptr);
      }
    }
    if (selectIn.find(cur->getId()) != selectIn.end()) {
      for (auto edge : selectIn[cur->getId()]) {
        for (auto src : edge.second) {
          Prop(pag->getGNode(src), edge.first, true, nullptr);
        }
      }
    }
    if (phiIn.find(cur->getId()) != phiIn.end()) {
      for (auto edge : phiIn[cur->getId()]) {
        for (auto src : edge.second) {
          Prop(pag->getGNode(src), edge.first, true, nullptr);
        }
      }
    }
    if (Formal2Real.find(cur->getId()) != Formal2Real.end()) {
      for (auto real : Formal2Real[cur->getId()]) {
        Prop(pag->getGNode(real), nullptr, true, pag->getGNode(real));
      }
    }
    if (cur->hasIncomingEdges(PAGEdge::Call)) {
      for (auto edge : cur->getIncomingEdges(PAGEdge::Call)) {
        auto callee = SVFUtil::getCallee(
            dyn_cast<CallPE>(edge)->getCallInst()->getCallSite());
        if (callee && isMemAllocFunction(callee->getName())) {
          continue;
        }
        Prop(edge->getSrcNode(), edge, true, nullptr);
      }
    }
    if (Call2Ret.find(cur->getId()) != Call2Ret.end()) {
      for (auto ret : Call2Ret[cur->getId()]) {
        Prop(pag->getGNode(ret), nullptr, true, cur);
      }
    }
    if (cur->hasIncomingEdges(PAGEdge::Ret)) {
      for (auto edge : cur->getIncomingEdges(PAGEdge::Ret)) {
        auto callee = SVFUtil::getCallee(
            dyn_cast<RetPE>(edge)->getCallInst()->getCallSite());
        if (callee && isMemAllocFunction(callee->getName())) {
          continue;
        }
        Prop(edge->getSrcNode(), edge, true, nullptr);
      }
    }
  }

  if (HistoryAwareStack.size() > 1 && cur->hasOutgoingEdges(PAGEdge::Store)) {
    for (auto edge : cur->getOutgoingEdges(PAGEdge::Store)) {
      auto dstNode = edge->getDstNode();
      PNwithOffset newTypeInfo(0, false);
      HistoryAwareStack.push(&newTypeInfo);
      Prop(dstNode, edge, true, nullptr);
      HistoryAwareStack.pop();
    }
  }

  if (state && cur->hasIncomingEdges(PAGEdge::Load)) {
    for (auto edge : cur->getIncomingEdges(PAGEdge::Load)) {
      auto srcNode = edge->getSrcNode();
      PNwithOffset newTypeInfo(0, true);
      HistoryAwareStack.push(&newTypeInfo);
      Prop(srcNode, edge, true, nullptr);
      HistoryAwareStack.pop();
    }
  }

  if (state && HistoryAwareStack.size() > 1) {
    auto topItem = HistoryAwareStack.top();
    if (topItem->curFlow && cur->hasIncomingEdges(PAGEdge::Addr)) {
      for (auto edge : cur->getIncomingEdges(PAGEdge::Addr)) {
        Prop(edge->getSrcNode(), edge, true, nullptr);
      }
    }
  }

  if (cur->hasOutgoingEdges(PAGEdge::Addr)) {
    for (auto edge : cur->getOutgoingEdges(PAGEdge::Addr)) {
      Prop(edge->getDstNode(), edge, false, nullptr);
    }
  }

  if (state && cur->hasIncomingEdges(PAGEdge::Gep)) {
    for (auto edge : cur->getIncomingEdges(PAGEdge::Gep)) {
      if (!HistoryAwareStack.empty()) {
        auto topItem = HistoryAwareStack.top();
        if (variantGep.find(edge) != variantGep.end()) {
          Prop(edge->getSrcNode(), edge, true, nullptr);
        } else if (gep2byteoffset.find(edge) != gep2byteoffset.end()) {
          // Consider taking shortcut?
          bool alltaked = false;
          const auto offset = gep2byteoffset[edge];
          if (!taken && ifValidForTypebasedShortcut(edge, baseNum * baseNum)) {
            taken = true;
            unordered_set<PAGNode *> visitedShortcuts;
            auto sttype = ifPointToStruct(edge->getSrcNode()->getType());
            const auto stname = getStructName(sttype);
            if (typebasedShortcuts.find(stname) != typebasedShortcuts.end() &&
                typebasedShortcuts[stname].find(offset) !=
                    typebasedShortcuts[stname].end()) {
              for (auto dstShort : typebasedShortcuts[stname][offset]) {
                Prop(dstShort->getDstNode(), dstShort, false, nullptr);
                visitedShortcuts.insert(dstShort->getDstNode());
              }
            }

            if (additionalShortcuts.find(stname) != additionalShortcuts.end() &&
                additionalShortcuts[stname].find(offset) !=
                    additionalShortcuts[stname].end()) {
              for (auto dstSet : additionalShortcuts[stname][offset]) {
                for (auto dstShort : *dstSet) {
                  if (visitedShortcuts.insert(dstShort->getDstNode()).second) {
                    Prop(dstShort->getDstNode(), dstShort, false, nullptr);
                  }
                }
              }
            }

            if (ifValidForCastSiteShortcut(edge, baseNum * baseNum)) {
              if (castSites.find(stname) != castSites.end()) {
                for (auto dstCast : castSites[stname]) {
                  bool needVisitDst = false;
                  bool needVisitSrc = false;
                  if (auto castSrcTy = dstCast->getSrcNode()->getType()) {
                    if (auto castSrcSt = ifPointToStruct(castSrcTy)) {
                      if (getStructName(castSrcSt) == stname) {
                        needVisitDst = true;
                      } else {
                        needVisitSrc = true;
                      }
                    } else {
                      needVisitSrc = true;
                    }
                  } else {
                    needVisitSrc = true;
                  }
                  if (auto castDstTy = dstCast->getDstNode()->getType()) {
                    if (auto castDstSt = ifPointToStruct(castDstTy)) {
                      if (getStructName(castDstSt) == getStructName(sttype)) {
                        needVisitSrc = true;
                      } else {
                        needVisitDst = true;
                      }
                    } else {
                      needVisitDst = true;
                    }
                  } else {
                    needVisitDst = true;
                  }
                  if (needVisitSrc) {
                    topItem->offset -= offset;
                    Prop(dstCast->getSrcNode(), dstCast, true, nullptr);
                    topItem->offset += offset;
                  }
                  if (needVisitDst) {
                    topItem->offset -= offset;
                    Prop(dstCast->getDstNode(), dstCast, false, nullptr);
                    topItem->offset += offset;
                  }
                }
              }
              alltaked = true;
            }
            taken = false;
          }
          if (!alltaked) {
            topItem->offset -= offset;
            Prop(edge->getSrcNode(), edge, true, nullptr);
            topItem->offset += offset;
          }
        }
      }
    }
  }

  if (HistoryAwareStack.size() > 1 && cur->hasOutgoingEdges(PAGEdge::Gep)) {
    for (auto edge : cur->getOutgoingEdges(PAGEdge::Gep)) {
      auto topItem = HistoryAwareStack.top();
      if (variantGep.find(edge) != variantGep.end()) {
        Prop(edge->getDstNode(), edge, true, nullptr);
      } else if (gep2byteoffset.find(edge) != gep2byteoffset.end()) {
        topItem->offset += gep2byteoffset[edge];
        Prop(edge->getDstNode(), edge, true, nullptr);
        topItem->offset -= gep2byteoffset[edge];
      }
    }
  }
}