
/**
 * @file binCountSketchValue.h
 * @brief This file contains the declaration of the binCountSketchValue class, which implements BC-sketch algorithm.
 * @author Mikuláš Brázda
 * @date 15.05.2024
 */

#pragma once

#include <iostream>
#include <bitset>

/**
 * @brief A class representing a bin count sketch value.
 * 
 * @tparam noBits The number of bits in the bin count sketch value.
 */
template<int noBits>
class binCountSketchValue {    
public:
    using Key = std::bitset<noBits>;

    /**
     * @brief Constructs a binCountSketchValue object with an initial value.
     * 
     * @param initialValue The initial value for the binCountSketchValue object.
     */
    binCountSketchValue(u_int32_t initialValue = 0);

    /**
     * @brief Gets the total count of the binCountSketchValue object.
     * 
     * @return The total count.
     */
    u_int32_t getTotalCount() const;

    /**
     * @brief Reverses the key of the binCountSketchValue object.
     * 
     * @return The reversed key.
     */
    Key reverseKey() const;

    /**
     * @brief Updates the binCountSketchValue object with a key and value.
     * 
     * @param key The key to update.
     * @param value The value to update.
     */
    void update(const Key& key, uint16_t value);


    /**
     * @brief Overloads the -= operator to subtract another binCountSketchValue object.
     * 
     * @param other The other binCountSketchValue object to subtract.
     * @return The updated binCountSketchValue object.
     */
    binCountSketchValue<noBits>& operator-=(const binCountSketchValue<noBits>& other);

    /**
     * @brief Overloads the += operator to add another binCountSketchValue object.
     * 
     * @param other The other binCountSketchValue object to add.
     * @return The updated binCountSketchValue object.
     */
    binCountSketchValue<noBits>& operator+=(const binCountSketchValue<noBits>& other);

    /**
     * @brief Converts the binCountSketchValue object to an integer.
     * 
     * @return The binCountSketchValue object as an integer.
     */
    operator int() const { return totalCount; }

private:
    uint32_t totalCount; // The total count
    uint32_t binCount[noBits]; // The bin counts
};

#include "../src/binCountSketchValue.tpp" // Include the implementation file
