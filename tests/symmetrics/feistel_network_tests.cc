#include "feistel_network.h"
#include <array>
#include <cstring>
#include <gtest/gtest.h>
#include <memory>
#include <ostream>
#include <sstream>
#include <string>
template <int size_block, int count_block, int size_key, int size_round_key>
class EmptyFeistelNetworkTest
    : public FeistelNetwork<size_block, count_block, size_key, size_round_key> {
public:
  EmptyFeistelNetworkTest(std::array<std::byte, size_key> key, int rounds)
      : FeistelNetwork<size_block, count_block, size_key, size_round_key>(
            key, rounds) {}

protected:
  virtual std::array<std::byte, size_round_key> get_round_key(int i) override {
    return std::array<std::byte, size_round_key>{};
  }
  virtual std::array<std::byte, size_block> f(const char *first,
                                              const char *key) override {
    return std::array<std::byte, size_block>{};
  }

  virtual void append(char *target, const char *value) override {}
};
class SimplyFeistelNetwork : public EmptyFeistelNetworkTest<1, 2, 3, 1> {
public:
  SimplyFeistelNetwork()
      : EmptyFeistelNetworkTest<1, 2, 3, 1>(std::array<std::byte, 3>{}, 3) {
    _key[0] = (std::byte)1;
    _key[1] = (std::byte)2;
    _key[2] = (std::byte)3;
  }

protected:
  virtual std::array<std::byte, 1> get_round_key(int i) override {
    auto res = std::array<std::byte, 1>{(std::byte)this->_key[i]};
    return res;
  }
  virtual std::array<std::byte, 1> f(const char *first,
                                     const char *key) override {
    std::array<std::byte, 1> res;
    res[0] = std::byte(1);
    return res;
  }
  virtual void append(char *target, const char *value) override {
    target[0] += value[0];
  }
};
TEST(SymmetricsFeistelTests, EncryptionOneMoveBlocks) {
  EmptyFeistelNetworkTest<4, 3, 4, 1> network(std::array<std::byte, 4>{}, 1);
  std::array<char, 12> output;
  network.encryption("000011112222", output.data());
  ASSERT_EQ("111122220000", std::string(output.data(), output.size()));
}
TEST(SymmetricsFeistelTests, EncryptionTwoMoveBlocks) {

  EmptyFeistelNetworkTest<4, 3, 4, 1> network(std::array<std::byte, 4>{}, 2);
std::array<char, 12> output;
  network.encryption("000011112222", output.data());
  ASSERT_EQ("222200001111", std::string(output.data(), output.size()));
}
TEST(SymmetricsFeistelTests, EncryptionThreeMoveBlocks) {

  EmptyFeistelNetworkTest<4, 3, 4, 1> network(std::array<std::byte, 4>{}, 3);
  std::array<char, 12> output;
  network.encryption("000011112222", output.data());
  ASSERT_EQ("000011112222", std::string(output.data(), output.size()));
}
TEST(SymmetricsFeistelTests, EncryptionBlocks) {

  SimplyFeistelNetwork network;
std::array<char, 2> output;
  network.encryption("01", output.data());
  ASSERT_EQ("31", std::string(output.data(), output.size()));
}
TEST(SymmetricsFeistelTests, DecryptionBlocks) {
  SimplyFeistelNetwork network;
std::array<char, 2> output;
  network.decryption("01", output.data());
  ASSERT_EQ("31", std::string(output.data(),output.size()));
}
