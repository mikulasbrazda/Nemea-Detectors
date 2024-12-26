
/**
 * @file ddosDetectorValue.cpp
 * @brief This file contains the definition of the ddosDetectorValue class, which is stored in sketch.
 * @author Mikuláš Brázda
 * @date 15.05.2024
 */
#include "ddosDetectorValue.h"

ddosDetectorValue::ddosDetectorValue() : byteCount_(0), packetCount_(0), flowCount_(0), sentBytes_(0), sentFlows_(0), communicatedWith_() {  
};

void ddosDetectorValue::update(std::bitset<32> key, netflowRecord_t value) {
    uint8_t ipSubnet = value.dstAddr >> 24;
    ipSubnets_[ipSubnet] += 1;
    reversibleKey_.update(value.dstAddr, 1);
    byteCount_ += value.bytes;	
    packetCount_ += value.packets;
    flowCount_ += 1;
};
ddosDetectorValue& ddosDetectorValue::operator-= (const ddosDetectorValue& other) {
    reversibleKey_ -= other.reversibleKey_;
    byteCount_ = other.byteCount_ > byteCount_ ? 0 : byteCount_ - other.byteCount_;
    packetCount_ = other.packetCount_ > packetCount_ ? 0 : packetCount_ - other.packetCount_;
    sentBytes_ = other.sentBytes_ > sentBytes_ ? 0 : sentBytes_ - other.sentBytes_;
    sentFlows_ = other.sentFlows_ > sentFlows_ ? 0 : sentFlows_ - other.sentFlows_;
    flowCount_ = other.flowCount_ > flowCount_ ? 0 : flowCount_ - other.flowCount_;
    for (auto& [key, value] : other.communicatedWith_) {
        auto it = communicatedWith_.find(key);
        if (it != communicatedWith_.end()) {
            if (it->second > value) {
                it->second -= value;
            } else {
                communicatedWith_.erase(it);
            }
        }
    }
    for (auto& [key, value] : other.ipSubnets_) {
        auto it = ipSubnets_.find(key);
        if (it != ipSubnets_.end()) {
            if (it->second > value) {
                it->second -= value;
            } else {
                ipSubnets_.erase(it);
            }
        }
    }
    return *this;
}
ddosDetectorValue& ddosDetectorValue::operator+= (const ddosDetectorValue& other) {
    reversibleKey_ += other.reversibleKey_;
    byteCount_ += other.byteCount_;
    packetCount_ += other.packetCount_;
    sentBytes_ += other.sentBytes_;
    sentFlows_ += other.sentFlows_;
    flowCount_ += other.flowCount_;
    
    for (auto& [key, value] : other.ipSubnets_) {
        ipSubnets_[key] += value;
    }
    for (auto& [key, value] : other.communicatedWith_) {
        communicatedWith_[key] += value;
    }
    return *this;
}
void ddosDetectorValue::updateSentBytes(const uint64_t sentBytes) {
    sentBytes_ += sentBytes;
    sentFlows_ += 1;
};

void ddosDetectorValue::updateFlowCounter(const uint32_t index) {
    communicatedWith_[index] += 1;
};

uint64_t ddosDetectorValue::getSentBytes() const {
    return sentBytes_;
};

uint32_t ddosDetectorValue:: getSentFlows() const {
    return sentFlows_;
};

uint32_t ddosDetectorValue::getPacketCount() const {
    return packetCount_;
};

uint64_t ddosDetectorValue::getByteCount() const {
    return byteCount_;
};

uint32_t ddosDetectorValue::getFlowCount() const {
    return flowCount_;
};

std::bitset<32> ddosDetectorValue::reverseKey() const {
    return reversibleKey_.reverseKey();
};

std::unordered_map<uint32_t, uint32_t> ddosDetectorValue::getCommunicatedWith() const {
    return communicatedWith_;
};

std::map<uint8_t, uint32_t> ddosDetectorValue::getipSubnets() const {
    return ipSubnets_;
};
