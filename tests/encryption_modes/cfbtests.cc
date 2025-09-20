#include "cfb.h"
#include <gtest/gtest.h>
#include <memory>
#include <simply_symmetric.h>
#include <sstream>
#include <string>
TEST(CFBTests, Encrypt_Full_Blocks) {
  auto encryptor = std::make_shared<SimplySymmetric>();

  CFB<2> cbc(encryptor);

  std::vector<char> key = {0x50, 0x70};
  std::vector<char> buf(2);
  cbc.init(key, 1);
  std::shared_ptr<std::stringstream> input =
      std::make_shared<std::stringstream>();
  std::shared_ptr<std::stringstream> output =
      std::make_shared<std::stringstream>();

  std::string in_str = "abcd";
  *input << in_str;
  cbc.encryption(input, output);
  for (int i = 0; i < in_str.size(); ++i) {
    encryptor->encryption(key.data(), buf.data());
    in_str[i] ^= buf[0];
    key[0] = key[1];
    key[1] = in_str[i];
  }
  ASSERT_EQ(output->str(), in_str);
}
TEST(CFBTests, Decrypt_Full_Blocks) {

  auto encryptor = std::make_shared<SimplySymmetric>();

  CFB<2> cbc(encryptor);

  std::vector<char> key = {0x50, 0x70};
  std::vector<char> buf(2);
  cbc.init(key, 1);
  std::shared_ptr<std::stringstream> input =
      std::make_shared<std::stringstream>();
  std::shared_ptr<std::stringstream> output =
      std::make_shared<std::stringstream>();

  std::string in_str = "abcd";
  *input << in_str;
  cbc.decryption(input, output);

  for (int i = 0; i < in_str.size(); ++i) {
    encryptor->encryption(key.data(), buf.data());
    key[0] = key[1];
    key[1] = in_str[i];
    in_str[i] ^= buf[0];
  }
  ASSERT_EQ(output->str(), in_str);
}
TEST(CFBTests, Encrypt_And_Decrypt_Full_Blocks) {

  auto encryptor = std::make_shared<SimplySymmetric>();

  CFB<2> cbc(encryptor);

  std::vector<char> key = {0x50, 0x70};
  std::vector<char> buf(2);
  cbc.init(key, 1);
  std::shared_ptr<std::stringstream> input =
      std::make_shared<std::stringstream>();
  std::shared_ptr<std::stringstream> output =
      std::make_shared<std::stringstream>();
  std::shared_ptr<std::stringstream> encrypted_text =
      std::make_shared<std::stringstream>();

  std::string in_str = "a";
  *input << in_str;
  cbc.encryption(input, output);

  cbc.decryption(output, encrypted_text);
  ASSERT_EQ(encrypted_text->str(), in_str);
}
TEST(CFBTests, Encrypt_Patition_Blocks) {
  auto encryptor = std::make_shared<SimplySymmetric>();

  CFB<2> cbc(encryptor);

  std::vector<char> key = {0x50, 0x70};
  std::vector<char> buf(2);
  cbc.init(key, 2);
  std::shared_ptr<std::stringstream> input =
      std::make_shared<std::stringstream>();
  std::shared_ptr<std::stringstream> output =
      std::make_shared<std::stringstream>();

  std::string in_str = "abcd";
  *input << "abc";
  cbc.encryption(input, output);
  encryptor->encryption(key.data(), buf.data());
  in_str[0] ^= buf[0];
  in_str[1] ^= buf[1];

  key[0] = in_str[0];
  key[1] = in_str[1];
  encryptor->encryption(key.data(), buf.data());
  in_str[2] ^= buf[0];
  in_str[3] = 0 ^ buf[1];

  ASSERT_EQ(output->str(), in_str);
}
TEST(CFBTests, Decrypt_Partition_Blocks) {
  auto encryptor = std::make_shared<SimplySymmetric>();

  CFB<2> cbc(encryptor);

  std::vector<char> key = {0x50, 0x70};
  std::vector<char> buf(2);
  cbc.init(key, 2);
  std::shared_ptr<std::stringstream> input =
      std::make_shared<std::stringstream>();
  std::shared_ptr<std::stringstream> output =
      std::make_shared<std::stringstream>();

  std::string in_str = "abcd";
  *input << "abc";
  cbc.decryption(input, output);
  encryptor->encryption(key.data(), buf.data());
  key[0] = in_str[0];
  key[1] = in_str[1];
  in_str[0] ^= buf[0];
  in_str[1] ^= buf[1];
  encryptor->encryption(key.data(), buf.data());
  in_str[2] ^= buf[0];
  in_str[3] = 0 ^ buf[1];

  ASSERT_EQ(output->str(), in_str);
}
TEST(CFBTests, Encrypt_And_Decrypt_Partition_Blocks) {

  auto encryptor = std::make_shared<SimplySymmetric>();

  CFB<2> cbc(encryptor);

  std::vector<char> key = {0x50, 0x70};
  std::vector<char> buf(2);
  cbc.init(key, 2);
  std::shared_ptr<std::stringstream> input =
      std::make_shared<std::stringstream>();
  std::shared_ptr<std::stringstream> output =
      std::make_shared<std::stringstream>();
  std::shared_ptr<std::stringstream> encrypted_text =
      std::make_shared<std::stringstream>();

  std::string in_str = "abcd";
  in_str[3] = 0;
  *input << "abc";
  cbc.encryption(input, output);

  cbc.decryption(output, encrypted_text);
  ASSERT_EQ(encrypted_text->str(), in_str);
}
