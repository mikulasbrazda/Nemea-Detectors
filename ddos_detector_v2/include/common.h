
/**
 * @file common.h
 * @brief This file contains common utility functions and structures used in the project.
 * @author Mikuláš Brázda
 * @date 15.05.2024
 */

#pragma once

#include <iostream>
#include <vector>
#include <arpa/inet.h>

struct NoValueStorage {};

/**
 * @brief Template struct to check if a type is NoValueStorage.
 * @tparam T The type to check.
 */
template<typename T>
struct IsNoValueStorage {
    static constexpr bool value = std::is_same<T, NoValueStorage>::value;
};

/**
 * @brief Structure representing a netflow record.
 * 
 * This structure contains information about a netflow record, including the source address,
 * destination address, number of packets, and number of bytes.
 */
typedef struct netflowRecord {
    uint32_t srcAddr;
    uint32_t dstAddr;
    uint64_t packets;
    uint64_t bytes;
} netflowRecord_t;

/**
 * @brief Calculates the quantile of a sorted vector.
 * @tparam T The type of elements in the vector.
 * @param sortedVec The sorted vector.
 * @param quantile The quantile value (between 0 and 1).
 * @return The quantile value.
 */
template<typename T>
float getQuantileSortedVec(std::vector<T>& sortedVec, const float quantile) {

    // Calculate the position
    float index = (sortedVec.size() - 1) * quantile;

    // Interpolate if necessary
    uint32_t lowerIndex = static_cast<uint32_t>(index);
    uint32_t upperIndex = lowerIndex + 1;
    float interpolation = index - lowerIndex;
    if (upperIndex >= sortedVec.size()) {
        // If the index is at the upper end, return the last element
        return sortedVec.back();
    } else {
        // Interpolate between the two surrounding values
        return sortedVec[lowerIndex] * (1 - interpolation) + sortedVec[upperIndex] * interpolation;
    }
}


