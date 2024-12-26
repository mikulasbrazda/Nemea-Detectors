
/**
 * @file ddosDetectorValue.h
 * @brief This file contains the declaration of the ddosDetectorValue class, which is stored in sketch.
 * @author Mikuláš Brázda
 * @date 15.05.2024
 */
#pragma once

#include "binCountSketchValue.h"
#include <bitset>
#include <unordered_map>
#include <set> 
#include <map>
#include "common.h"

/**
 * @brief Class representing a DDoS detector value.
 * 
 * This class stores various statistics related to DDoS detection, such as the number of sent bytes,
 * the number of sent flows, the packet count, the byte count, the flow count, the reversible key,
 * the communication records, and the IP subnets.
 */
class ddosDetectorValue {
public:
    /**
     * @brief Default constructor for ddosDetectorValue.
     */
    ddosDetectorValue();

    /**
     * @brief Updates the ddosDetectorValue with a new key-value pair.
     * 
     * @param key The key to update.
     * @param value The value to update.
     */
    void update(std::bitset<32> key, netflowRecord_t value);

    /**
     * @brief Subtracts the values of another ddosDetectorValue from this ddosDetectorValue.
     * 
     * @param other The ddosDetectorValue to subtract.
     * @return A reference to this ddosDetectorValue after subtraction.
     */
    ddosDetectorValue& operator-= (const ddosDetectorValue& other);

    /**
     * @brief Adds the values of another ddosDetectorValue to this ddosDetectorValue.
     * 
     * @param other The ddosDetectorValue to add.
     * @return A reference to this ddosDetectorValue after addition.
     */
    ddosDetectorValue& operator+= (const ddosDetectorValue& other);

    /**
     * @brief Updates the number of sent bytes.
     * 
     * @param sentBytes The number of sent bytes to update.
     */
    void updateSentBytes(const uint64_t sentBytes);

    /**
     * @brief Updates the flow counter.
     * 
     * @param index The index of the flow counter to update.
     */
    void updateFlowCounter(const uint32_t index);

    /**
     * @brief Gets the number of sent bytes.
     * 
     * @return The number of sent bytes.
     */
    uint64_t getSentBytes() const;

    /**
     * @brief Gets the number of sent flows.
     * 
     * @return The number of sent flows.
     */
    uint32_t getSentFlows() const;

    /**
     * @brief Gets the packet count.
     * 
     * @return The packet count.
     */
    uint32_t getPacketCount() const;

    /**
     * @brief Gets the byte count.
     * 
     * @return The byte count.
     */
    uint64_t getByteCount() const;

    /**
     * @brief Gets the flow count.
     * 
     * @return The flow count.
     */
    uint32_t getFlowCount() const;

    /**
     * @brief Reverses the key.
     * 
     * @return The reversed key.
     */
    std::bitset<32> reverseKey() const;

    /**
     * @brief Gets the communication records.
     * 
     * @return The communication records.
     */
    std::unordered_map<uint32_t, uint32_t> getCommunicatedWith() const;

    /**
     * @brief Gets the IP subnets.
     * 
     * @return The IP subnets.
     */
    std::map<uint8_t, uint32_t> getipSubnets() const;

private:
    uint64_t sentBytes_;                                    // Number of sent bytes
    uint32_t sentFlows_;                                    // Number of sent flows
    uint32_t packetCount_;                                  // Packet count
    uint64_t byteCount_;                                    // Byte count
    uint32_t flowCount_;                                    // Flow count
    binCountSketchValue<32> reversibleKey_;                 // Reversible key
    std::unordered_map<uint32_t, uint32_t> communicatedWith_;   // Communication records
    std::map<uint8_t, uint32_t> ipSubnets_;                  // IP subnets
};
