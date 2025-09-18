#include "ecb.h"
#include "isymmetric.h"
#include <gtest/gtest.h>
#include <memory>
#include <simply_symmetric.h>
#include <sstream>

TEST(ECBTests, Encrypt_Full_Blocks) {
  ECB<2> ecb(std::make_shared<SimplySymmetric>());
  std::shared_ptr<std::stringstream> input =
      std::make_shared<std::stringstream>();
  std::shared_ptr<std::stringstream> output =
      std::make_shared<std::stringstream>();
  *input << "abcd";
  ecb.encryption(input, output);
  ASSERT_EQ(output->str(), "bbdd");
}
TEST(ECBTests, Decrypt_Full_Blocks) {
  ECB<2> ecb(std::make_shared<SimplySymmetric>());
  std::shared_ptr<std::stringstream> input =
      std::make_shared<std::stringstream>();
  std::shared_ptr<std::stringstream> output =
      std::make_shared<std::stringstream>();
  *input << "bbdd";
  ecb.decryption(input, output);
  ASSERT_EQ(output->str(), "abcd");
}
TEST(ECBTests, Encrypt_partable_Blocks) {
  ECB<2> ecb(std::make_shared<SimplySymmetric>());
  std::shared_ptr<std::stringstream> input =
      std::make_shared<std::stringstream>();
  std::shared_ptr<std::stringstream> output =
      std::make_shared<std::stringstream>();
  *input << "abc";
  ecb.encryption(input, output);
  ASSERT_EQ(output->str(), "bbd");
}
TEST(ECBTests, Decrypt_partable_Blocks) {
  ECB<2> ecb(std::make_shared<SimplySymmetric>());
  std::shared_ptr<std::stringstream> input =
      std::make_shared<std::stringstream>();
  std::shared_ptr<std::stringstream> output =
      std::make_shared<std::stringstream>();
  *input << "bbd";
  ecb.decryption(input, output);
  ASSERT_EQ(output->str(), "abc");
}
