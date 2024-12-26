
/**
 * @file ddosDetector.cpp
 * @brief This file contains the definition of the ddosDetector class which implements detection of DDoS attacks using CUSUMs.
 * @author Mikuláš Brázda
 * @date 15.05.2024
 */

#include "ddosDetector.h"
#include <arpa/inet.h>
#include <timeManager.h>
#include <fstream>
#include <filesystem>
#include <numeric>
#include <ranges>

// Variadic template function using fold expression
template<typename... Args>
void debugPrint(std::ostream& out, bool appendEndln, Args... args) {
    #ifdef DEBUG
        // Use fold expression to output all arguments
        ((out << args << " "), ...);
        if (appendEndln) {
            out << std::endl;
        }
    #endif
}
ddosDetector::ddosDetector(Trie<float>& protectedPrefixes, 
                            std::optional<Trie<>>& whitelistedPrefixes,
                            size_t learningSecs, 
                            float quantile,
                            float alpha,
                            uint32_t span,
                            float c,
                            size_t outerSizeDstIPs,
                            size_t innerSizeDstIPs,
                            size_t outerSizeSrcIPs,
                            size_t innerSizeSrcIPs,
                            int n,
                            int timeBetweenAlertsSecs) : 
                            protectedPrefixes(protectedPrefixes),
                            learningSecs_(learningSecs),
                            quantile_(quantile),
                            stop(false),
                            innerSizeDstIPs(innerSizeDstIPs),
                            innerSizeSrcIPs(innerSizeSrcIPs),
                            outerSizeSrcIPs(outerSizeSrcIPs),
                            outerSizeDstIPs(outerSizeDstIPs),
                            n_(n),
                            dstIPs(outerSizeDstIPs, innerSizeDstIPs, learningSecs == 0, learningSecs != 0),
                            srcIPs(outerSizeSrcIPs, innerSizeSrcIPs, learningSecs == 0, learningSecs != 0),
                            cusumBytes(std::vector<AdaptiveCUSUM>(innerSizeDstIPs, AdaptiveCUSUM(c, alpha, span))),
                            cusumPackets(std::vector<AdaptiveCUSUM>(innerSizeDstIPs, AdaptiveCUSUM(c, alpha, span))),
                            cusumEntropy(std::vector<AdaptiveCUSUM>(innerSizeDstIPs, AdaptiveCUSUM(c, alpha, span))),
                            cusumBytesReceivedToSent(std::vector<AdaptiveCUSUM>(innerSizeDstIPs, AdaptiveCUSUM(c, alpha, span))),
                            cusumFlowsReceivedToSent(std::vector<AdaptiveCUSUM>(innerSizeDstIPs, AdaptiveCUSUM(c, alpha, span))),
                            timeBetweenAlertsSecs_(timeBetweenAlertsSecs) {
    if (whitelistedPrefixes) {
        this->whitelistedPrefixes = std::move(whitelistedPrefixes.value());
    } else {
        this->whitelistedPrefixes = Trie();
    }
}

void ddosDetector::runDetectorThread() {
    // learn until current time + learning secs 
    detectorThread = std::thread(&ddosDetector::detectionProcess, this);
}

void ddosDetector::updateCommunicatedWith(uint32_t srcIP, uint32_t dstIP, uint64_t bytes, bool isDst) {
   uint32_t dstIPidx, srcIPidx;
    for (int i=0; i<outerSizeDstIPs; i++) {
        if (isDst) {
            srcIPidx = srcIPs.getCol(srcIP, i);
            dstIPidx = dstIPs.getCol(dstIP & 0x00FFFFFF, i);
            dstIPs[i][dstIPidx].value.updateFlowCounter(srcIPidx);
        } else {
            dstIPidx = dstIPs.getCol(srcIP & 0x00FFFFFF, i);
            dstIPs[i][dstIPidx].value.updateSentBytes(bytes);
        }
    }
}

void ddosDetector::processCurrentFlow(const netflowRecord_t& record) {
    
    in_addr srcAddr;
    // check if the destination IP is in the protected prefixes
    if (isProtected(record.dstAddr)) {
        // Update the dstIPs sketch
        dstIPs.update(record.dstAddr & 0x00FFFFFF, record);
        // Update the communicated with in the srcIPs
        updateCommunicatedWith(record.srcAddr, record.dstAddr, record.bytes, true);
    std::string strIP = inet_ntoa((in_addr)record.dstAddr);
    
    // check if the source IP is in the protected prefixes
    } else if (isProtected(record.srcAddr)) {
        // Update the sent bytes in the dstIPs
        updateCommunicatedWith(record.srcAddr, record.dstAddr, record.bytes, false);
     
    } else {
        return;
    }
    // src IPs always updated
    srcAddr.s_addr = record.srcAddr;
    // Update the srcIPs sketch
    srcIPs.update(record.srcAddr, 1);
}

bool ddosDetector::isProtected(uint32_t inputIP) const {
    return protectedPrefixes.searchPrefix(std::bitset<32>(ntohl(inputIP)).to_string());
}

bool ddosDetector::isWhitelisted(uint32_t inputIP) const {
    std::string binary = std::bitset<32>(ntohl(inputIP)).to_string();
    return protectedPrefixes.searchPrefix(binary) or whitelistedPrefixes.searchPrefix(binary);
}

float ddosDetector::getMultiplier(uint32_t ip) {
    float result = 0.0;
    protectedPrefixes.searchPrefix(std::bitset<32>(ntohl(ip)).to_string(), result);
    return result;
}

void ddosDetector::notifyWorker() {
    pipe.write(PipeValue{dstIPs, srcIPs});
    srcIPs.reset();
    dstIPs.reset();
}

float ddosDetector::calculateNormalizedEntropy(std::vector<uint32_t> counts) {
    double entropy = 0.0;
    if (counts.size() < 2)
        return 0.0;

    size_t totalCount = std::accumulate(counts.begin(), counts.end(), 0);
    for (auto& count : counts) {
        float frequency = static_cast<float>(count) / totalCount;
        entropy -= frequency * std::log2(frequency);
    }

    return entropy / std::log2(counts.size());
}

void ddosDetector::initFiles() {
    #ifdef DEBUG
        logFile.open("ddosDetector.log");
        statsFile.open("stats.csv");
        // write header only if file is empty
        statsFile << "WindowID,IP,bytes,packets,sent_recv_bytes,entropy,sent_recv_flows,SH_bytes,TH_bytes,"\
        "SH_packets,TH_packets,SH_entropy,TH_entropy,SL_entropy,TL_entropy,SH_sent_recv_bytes,TH_sent_recv_bytes,SH_sent_recv_flows,TH_sent_recv_flows,"\
        "M_bytes,M_packets,M_entropy,M_sent_recv_bytes,M_sent_recv_flows,"\
        "V_bytes,V_packets,V_entropy,V_sent_recv_bytes,V_sent_recv_flows,"\
        "maxSH_bytes,maxSH_packets,maxSH_entropy,maxSL_entropy,maxSH_sent_recv_bytes,maxSH_sent_recv_flows" << std::endl;
    #endif
}

void ddosDetector::updateThresholds() {
    std::ofstream thresholdFile("thresholds.csv");
    for (int j = 0; j < innerSizeDstIPs; ++j) {
        thresholdFile << cusumBytes[j].getThresholdHigh() << ",";
        thresholdFile << cusumPackets[j].getThresholdHigh() << ","; 
        thresholdFile << cusumEntropy[j].getThresholdHigh() << ",";
        thresholdFile << cusumEntropy[j].getThresholdLow() << ",";
        thresholdFile << cusumBytesReceivedToSent[j].getThresholdHigh() << ",";
        thresholdFile << cusumFlowsReceivedToSent[j].getThresholdHigh() << std::endl;
    }
    thresholdFile.close();
}

void ddosDetector::closeFiles() {
    #ifdef DEBUG
        logFile.close();
        statsFile.close();
    #endif
}

void ddosDetector::checkFalsePositives() {
    dos_alert_t falsePositive;
    if (dosFalsePositivesQueue.try_pop(falsePositive)) {
        float multiplier = getMultiplier(falsePositive.dstIP);
        cusumEntropy[falsePositive.cusumID].setThresholdHigh(falsePositive.measuredEntropy / multiplier);
        cusumBytes[falsePositive.cusumID].setThresholdHigh(falsePositive.measuredBytes / multiplier);
        cusumPackets[falsePositive.cusumID].setThresholdHigh(falsePositive.measuredPackets / multiplier);
        cusumBytesReceivedToSent[falsePositive.cusumID].setThresholdHigh(falsePositive.measuredBytesReceivedToSent / multiplier);
        cusumFlowsReceivedToSent[falsePositive.cusumID].setThresholdHigh(falsePositive.measuredFlowsReceivedToSent / multiplier);
    } 
}

void ddosDetector::reverseSrcIPs(const std::unordered_map<uint32_t, uint32_t>& communicatedWith, 
                                    std::vector<std::pair<uint32_t, uint32_t>>& srcIPsCommWithDstVec, 
                                    const std::map<uint32_t, uint32_t>& rows, 
                                    BCSketchTypeSrcIPs& srcIPsCopy) {
    for (auto& srcIPidx : communicatedWith) {
        uint32_t row = rows.at(srcIPidx.first);
        uint32_t prevCnt = 0;
        while (prevCnt != srcIPsCopy[row][srcIPidx.first].count) {
            prevCnt = srcIPsCopy[row][srcIPidx.first].count;
            const uint32_t recoveredSrcIP = srcIPsCopy[row][srcIPidx.first].value.reverseKey().to_ulong();
            std::pair<uint32_t, uint32_t> recoveredIPCell = srcIPsCopy.estimate(recoveredSrcIP);
            auto cell = srcIPsCopy[recoveredIPCell.first][recoveredIPCell.second];
            if (cell.count == 0)
                break;
            srcIPsCommWithDstVec.push_back(std::pair(recoveredSrcIP, srcIPidx.second));
        }
    }
}

void ddosDetector::reverseAllKeys(uint32_t& maxIP, ddosDetectorValue& resultCell, BCSketchTypeDstIPs& dstIPs, 
                                BCSketchTypeSrcIPs& srcIPs, uint32_t column, 
                                std::vector<std::pair<uint32_t, uint32_t>>& srcIPsCommWithDst, 
                                std::set<uint32_t>& reversedPrefixes) {
    uint32_t prevCnt = 0;
    uint64_t maxIPBytes = 0;
    in_addr dstAddr, onlyPrefix;
    std::map<uint32_t, uint32_t> rows;
    while (prevCnt != dstIPs[0][column].count) {
        prevCnt = dstIPs[0][column].count;
        dstAddr.s_addr = dstIPs[0][column].value.reverseKey().to_ulong();
        onlyPrefix.s_addr = dstAddr.s_addr & 0x00FFFFFF;
        
        std::pair<uint32_t, uint32_t> indices = dstIPs.estimate(onlyPrefix.s_addr);
        auto cell = dstIPs[indices.first][indices.second];
        if (cell.count == 0 or not isProtected(onlyPrefix.s_addr)) {
            break;
        }
       
        if (maxIPBytes < cell.value.getByteCount())
        {
            maxIPBytes = cell.value.getByteCount();
            maxIP = onlyPrefix.s_addr;
        }
        for (auto& srcIP : cell.value.getCommunicatedWith()) {
            rows[srcIP.first] = indices.first;
        }
        resultCell += cell.value;
        dstIPs.dec(onlyPrefix.s_addr, cell);
        #ifdef DEBUG
            reversedPrefixes.insert(onlyPrefix.s_addr);
        #endif
    } 
    if (maxIP == 0)
        return;
    reverseSrcIPs(resultCell.getCommunicatedWith(), srcIPsCommWithDst, rows, srcIPs);
}

void ddosDetector::updateStatsFile(std::set<uint32_t>& dstIpsReversed, 
                                    uint32_t j, const ddosDetectorValue& resultCell, 
                                    float entropy, 
                                    float sentReceivedBytesRatio, 
                                    float sentReceivedFlowsRatio) {
#ifdef DEBUG
    for (auto& dstIP : dstIpsReversed) {
        statsFile << cusumBytes[j].getWindowID()
                    << "," << inet_ntoa((in_addr)dstIP)
                    << "," << resultCell.getByteCount() 
                    << "," << resultCell.getPacketCount()
                    << "," << sentReceivedBytesRatio 
                    << "," << entropy 
                    << "," << sentReceivedFlowsRatio
                    << "," << cusumBytes[j].getSH()                                      
                    << "," << cusumBytes[j].getThresholdHigh()
                    << "," << cusumPackets[j].getSH()
                    << "," << cusumPackets[j].getThresholdHigh()
                    << "," << cusumEntropy[j].getSH() 
                    << "," << cusumEntropy[j].getThresholdHigh()
                    << "," << cusumEntropy[j].getSL() 
                    << "," << cusumEntropy[j].getThresholdLow()
                    << "," << cusumBytesReceivedToSent[j].getSH()
                    << "," << cusumBytesReceivedToSent[j].getThresholdHigh() 
                    << "," << cusumFlowsReceivedToSent[j].getSH()
                    << "," << cusumFlowsReceivedToSent[j].getThresholdHigh()
                    << "," << cusumBytes[j].getMean()
                    << "," << cusumPackets[j].getMean()
                    << "," << cusumEntropy[j].getMean()
                    << "," << cusumBytesReceivedToSent[j].getMean()
                    << "," << cusumFlowsReceivedToSent[j].getMean()
                    << "," << cusumBytes[j].getVariance()
                    << "," << cusumPackets[j].getVariance()
                    << "," << cusumEntropy[j].getVariance()
                    << "," << cusumBytesReceivedToSent[j].getVariance()
                    << "," << cusumFlowsReceivedToSent[j].getVariance()
                    << "," << cusumBytes[j].getMaxSH()
                    << "," << cusumPackets[j].getMaxSH()
                    << "," << cusumEntropy[j].getMaxSH()
                    << "," << cusumEntropy[j].getMaxSL()
                    << "," << cusumBytesReceivedToSent[j].getMaxSH()
                    << "," << cusumFlowsReceivedToSent[j].getMaxSH() << std::endl;
    
        std::string addr = inet_ntoa((in_addr)dstIP);
    }
#endif
}
void ddosDetector::computeMetrics(double& entropy, 
                                double& receivedToSentBytes, double& receivedToSentFlows, 
                                std::vector<std::pair<uint32_t, uint32_t>>& srcIPsCommWithDst,
                                ddosDetectorValue& resultCell)
{
    auto values = srcIPsCommWithDst | std::views::transform([](const auto& pair) { return pair.second; });
    std::vector<uint32_t> counts(values.begin(), values.end());
    double entropySrcIPs = calculateNormalizedEntropy(counts);
    auto ipSubnets = resultCell.getipSubnets();
    auto values_ = std::views::values(ipSubnets);
    std::vector<uint32_t> counts_(values_.begin(), values_.end());

    double entropyDstIPs8bits = calculateNormalizedEntropy(counts_);
    entropy = (entropySrcIPs + 1e-6) / (entropyDstIPs8bits + 1e-6);
    auto communicatedWith = resultCell.getCommunicatedWith();
    auto valuesFlows = srcIPsCommWithDst | std::views::transform([](const auto& pair) { return pair.second; });
    std::vector<uint32_t> countsFlows(valuesFlows.begin(), valuesFlows.end());
  
    receivedToSentBytes =  (1.0f + resultCell.getByteCount()) / (resultCell.getSentBytes() + 1.0f);
    receivedToSentFlows =  (1.0f + resultCell.getFlowCount()) / (resultCell.getSentFlows() + 1.0f); 
}

void ddosDetector::updateMetrics(std::vector<std::pair<uint32_t, uint32_t>>& srcIPsCommWithDst, std::set<uint32_t>& dstIpsReversed,
                                ddosDetectorValue& resultCell, bool learning, uint32_t column) 
{
    double entropy = 0.0;
    double receivedSentBytes = 0.0;
    double receivedSentFlows = 0.0;
    computeMetrics(entropy, receivedSentBytes, receivedSentFlows, srcIPsCommWithDst, resultCell);
    cusumBytes[column].process(resultCell.getByteCount(), learning);
    cusumPackets[column].process(resultCell.getPacketCount(), learning);
    cusumEntropy[column].process(entropy, learning);
    cusumBytesReceivedToSent[column].process(receivedSentBytes, learning);
    cusumFlowsReceivedToSent[column].process(receivedSentFlows, learning);
    updateStatsFile(dstIpsReversed, column, resultCell, entropy, receivedSentBytes, receivedSentFlows);
}


bool ddosDetector::detectAnomaly(uint32_t maxIP, uint32_t column, std::vector<std::pair<uint32_t, uint32_t>>& srcIPsCommWithDst) {
    float multiplier = getMultiplier(maxIP);
    if (cusumBytes[column].isPositiveAnomaly(multiplier) and 
        cusumPackets[column].isPositiveAnomaly(multiplier) and 
        cusumBytesReceivedToSent[column].isPositiveAnomaly(multiplier) and 
        cusumFlowsReceivedToSent[column].isPositiveAnomaly(multiplier) and 
        cusumEntropy[column].isPositiveAnomaly(multiplier)) {
        
        std::set<uint32_t> srcIPsRes;
        getTopNSrcIPs(srcIPsCommWithDst, srcIPsRes);

        if (!srcIPsRes.empty()) {
            dos_alert_t dosAlert {
                cusumBytes[column].getThresholdHigh()*multiplier,
                cusumPackets[column].getThresholdHigh()*multiplier,
                cusumBytesReceivedToSent[column].getThresholdHigh()*multiplier,
                cusumFlowsReceivedToSent[column].getThresholdHigh()*multiplier,
                cusumEntropy[column].getThresholdHigh()*multiplier,
                cusumBytes[column].getSH(),
                cusumPackets[column].getSH(),
                cusumBytesReceivedToSent[column].getSH(),
                cusumFlowsReceivedToSent[column].getSH(),
                cusumEntropy[column].getSH(),
                maxIP,
                column,
                srcIPsRes,                          
            };
            dosAlertsQueue.push(dosAlert);
            return true;
        }                    
    }
    return false;    
}

void ddosDetector::detectionProcess() {
    // open file for logs
    bool thresholdSet = false;
    bool learning = true;
    in_addr dstAddr;
    initFiles();
    timePoint learn_until = TimeManager::now() + std::chrono::seconds(learningSecs_); 
    while (true) 
    {   
        PipeValue val = pipe.read();
        if (stop)
        {
            updateThresholds();
            closeFiles();  
            return;
        }
        timePoint currTime = TimeManager::now();
        learning = currTime < learn_until;

        if (not thresholdSet and not learning) {
            setCusumTresholds();
            thresholdSet = true;
        }

        if (thresholdSet) {
           checkFalsePositives();
        }
        for (uint32_t j = 0; j < innerSizeDstIPs; ++j) {
   
            if (val.dstIPs[0][j].count == 0) {
                continue;
            }
                    
            uint32_t maxIP = 0;
            ddosDetectorValue resultCell{};
            std::vector<std::pair<uint32_t, uint32_t>> reversedSrcIPs;
            std::set<uint32_t> reversedDstPrefixes;
            reverseAllKeys(maxIP, resultCell, val.dstIPs, val.srcIPs, j, reversedSrcIPs, reversedDstPrefixes);           
            if (maxIP == 0)
                continue;  
            updateMetrics(reversedSrcIPs, reversedDstPrefixes, resultCell, learning, j);
            if (thresholdSet and ((cusumBytes[j].getLastAlert() + std::chrono::seconds(timeBetweenAlertsSecs_)) < currTime)) {
                bool alert = detectAnomaly(maxIP, j, reversedSrcIPs);
                if (alert) {
                    cusumBytes[j].setLastAlert(currTime);
                }
            }
   
        }
    }
}

void ddosDetector::getTopNSrcIPs(std::vector<std::pair<uint32_t, uint32_t>>& srcIPsCommWithDst, std::set<uint32_t>& topNSrcIPs) {    
    std::sort(srcIPsCommWithDst.begin(), srcIPsCommWithDst.end(), 
                [](std::pair<uint32_t, uint32_t>& a, std::pair<uint32_t, uint32_t>& b) { return a.second > b.second; });
    
    for (auto& srcIP : srcIPsCommWithDst) {
        if (isWhitelisted(srcIP.first)) {
            continue;
        } 
        topNSrcIPs.insert(srcIP.first);
        if (topNSrcIPs.size() == n_) {
            break;
        }
    }

}

void ddosDetector::setCusumTresholds() {
    if (learningSecs_ == 0) {   
        std::ifstream thresholdFile("thresholds.csv");
        std::string line, word;
        for (int j = 0; j < innerSizeDstIPs; ++j) {
            getline(thresholdFile, line);
            std::stringstream ss(line);
            getline(ss, word, ',');
            cusumBytes[j].setThresholdHigh(stof(word));
            getline(ss, word, ',');
            cusumPackets[j].setThresholdHigh(stof(word));
            getline(ss, word, ',');
            cusumEntropy[j].setThresholdHigh(stof(word));
            getline(ss, word, ',');
            cusumEntropy[j].setThresholdLow(stof(word));
            getline(ss, word, ',');
            cusumBytesReceivedToSent[j].setThresholdHigh(stof(word));   
            getline(ss, word, ',');
            cusumFlowsReceivedToSent[j].setThresholdHigh(stof(word)); 
        }
        thresholdFile.close();
        return;
    }

    float quantileTHBytes = getQuantileThresholdHigh(cusumBytes);
    float quantileTHEntropy = getQuantileThresholdHigh(cusumEntropy);
    float quantileTHBytesReceivedToSent = getQuantileThresholdHigh(cusumBytesReceivedToSent);
    float quantileTHPackets = getQuantileThresholdHigh(cusumPackets);
    float quantileTLEntropy = getQuantileThresholdLow(cusumEntropy);
    float quantileTHFlowsSentToReceived = getQuantileThresholdHigh(cusumFlowsReceivedToSent);
    
    
    for (int j = 0; j < innerSizeDstIPs; ++j) {
        setCusumThresholdHigh(cusumBytes[j], quantileTHBytes);
        setCusumThresholdHigh(cusumEntropy[j], quantileTHEntropy);
        setCusumThresholdHigh(cusumBytesReceivedToSent[j], quantileTHBytesReceivedToSent);
        setCusumThresholdHigh(cusumPackets[j], quantileTHPackets);
        setCusumThresholdLow(cusumEntropy[j], quantileTLEntropy);
        setCusumThresholdHigh(cusumFlowsReceivedToSent[j], quantileTHFlowsSentToReceived);
    }
} 

void ddosDetector::setCusumThresholdHigh(AdaptiveCUSUM& cusum, float quantileTHreshold) {
    if (cusum.getMaxSH() > 0) {
        cusum.setThresholdHigh(cusum.getMaxSH());
    } else {
        cusum.setThresholdHigh(quantileTHreshold);
    }
}

void ddosDetector::setCusumThresholdLow(AdaptiveCUSUM& cusum, float quantileTHreshold) {
    if (cusum.getMaxSL() > 0) {
        cusum.setThresholdLow(cusum.getMaxSL());
    } else {
        cusum.setThresholdLow(quantileTHreshold);
    }
}

bool ddosDetector::getAlert(dos_alert_t& alert) {
    return dosAlertsQueue.try_pop(alert);
}

void ddosDetector::pushFalsePositive(const dos_alert_t& alert) {
    dosFalsePositivesQueue.push(alert);
}

template<typename T>
float ddosDetector::getQuantileThresholdLow(const T& allCusums) {
    std::vector<float> tresholdsHigh;
    for (auto& cusum : allCusums) {
        if (cusum.getMaxSH() > 0) {
            tresholdsHigh.push_back(cusum.getMaxSH());
        }
    }
    if (tresholdsHigh.empty()) {
        return 0;
    }
    std::sort(tresholdsHigh.begin(), tresholdsHigh.end());
    return getQuantileSortedVec(tresholdsHigh, quantile_);
}
template<typename T>
float ddosDetector::getQuantileThresholdHigh(const T& allCusums) {
    std::vector<float> tresholdsLow;
    // take only nonzero elements
    for (auto& cusum : allCusums) {
        if (cusum.getMaxSL() > 0) {
            tresholdsLow.push_back(cusum.getMaxSL());
        }
    }
    
    if (tresholdsLow.empty()) {
        return 0;
    }
    // sort them from the lowest to the highest
    std::sort(tresholdsLow.begin(), tresholdsLow.end());
    return getQuantileSortedVec(tresholdsLow, quantile_);
}
    

ddosDetector::~ddosDetector() {
    stop = true;
    pipe.write(PipeValue{dstIPs, srcIPs});
    if (detectorThread.joinable()) {
        detectorThread.join();
    }
}
    
