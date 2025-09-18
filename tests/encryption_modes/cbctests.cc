#include "cbc.h"
#include "ecb.h"
#include "isymmetric.h"
#include <gtest/gtest.h>
#include <memory>
#include <simply_symmetric.h>
#include <sstream>
#include <stdexcept>
#include <string>
TEST(CBCTests, Encrypt_Full_Blocks) {
  auto encryptor = std::make_shared<SimplySymmetric>();

  CBC<2> cbc(encryptor);

  std::vector<char> key = {0x50, 0x70};
  cbc.init(key);
  std::shared_ptr<std::stringstream> input =
      std::make_shared<std::stringstream>();
  std::shared_ptr<std::stringstream> output =
      std::make_shared<std::stringstream>();

  std::string in_str = "abcd";
  *input << in_str;
  cbc.encryption(input, output);

  char out_str[4];
  in_str[0] ^= key[0];
  in_str[1] ^= key[1];
  encryptor->encryption(in_str.c_str(), out_str);

  in_str[2] ^= out_str[0];
  in_str[3] ^= out_str[1];
  encryptor->encryption(in_str.c_str() + 2, out_str + 2);
  ASSERT_EQ(output->str(), std::string(out_str));
}
TEST(CBCTests, Decrypt_Full_Blocks) {
  auto encryptor = std::make_shared<SimplySymmetric>();

  CBC<2> cbc(encryptor);

  std::vector<char> key = {0x50, 0x70};
  cbc.init(key);
  std::shared_ptr<std::stringstream> input =
      std::make_shared<std::stringstream>();
  std::shared_ptr<std::stringstream> output =
      std::make_shared<std::stringstream>();

  std::string in_str = "abcd";
  *input << in_str;
  cbc.decryption(input, output);

  char out_str[4];
  encryptor->decryption(in_str.c_str() + 2, out_str + 2);
  out_str[2] ^= in_str[0];
  out_str[3] ^= in_str[1];

  encryptor->decryption(in_str.c_str(), out_str);
  out_str[0] ^= key[0];
  out_str[1] ^= key[1];
  ASSERT_EQ(output->str(), std::string(out_str));
}
TEST(CBCTests, Encrypt_Patition_Blocks) {
  auto encryptor = std::make_shared<SimplySymmetric>();

  CBC<2> cbc(encryptor);

  std::vector<char> key = {0x50, 0x70};
  cbc.init(key);
  std::shared_ptr<std::stringstream> input =
      std::make_shared<std::stringstream>();
  std::shared_ptr<std::stringstream> output =
      std::make_shared<std::stringstream>();

  std::string in_str = "abc";
  *input << in_str;
  cbc.encryption(input, output);
  in_str.push_back(0);
  char out_str[4];
  in_str[0] ^= key[0];
  in_str[1] ^= key[1];
  encryptor->encryption(in_str.c_str(), out_str);

  in_str[2] ^= out_str[0];
  in_str[3] ^= out_str[1];
  encryptor->encryption(in_str.c_str() + 2, out_str + 2);
  ASSERT_EQ(output->str(), std::string(out_str));
}
TEST(CBCTests, Decrypt_Partition_Blocks) {
  auto encryptor = std::make_shared<SimplySymmetric>();

  CBC<2> cbc(encryptor);

  std::vector<char> key = {0x50, 0x70};
  cbc.init(key);
  std::shared_ptr<std::stringstream> input =
      std::make_shared<std::stringstream>();
  std::shared_ptr<std::stringstream> output =
      std::make_shared<std::stringstream>();

  std::string in_str = "abc";
  *input << in_str;
  ASSERT_THROW(cbc.decryption(input, output), std::invalid_argument);
}
