#ifndef CFBCRYPTIONMODES_ECB_CPP
#define CFBCRYPTIONMODES_ECB_CPP
#include "cfb.h"
#include <algorithm>
#include <cstring>
#include <stdexcept>
#include <utility>
#include <vector>

template <int size_key>
void CFB<size_key>::init(const std::vector<char> &init_vector, int block_size) {
  if (init_vector.size() != this->encryptor->get_size_block()) {
    throw std::invalid_argument("init_vector");
  }
  this->_init_vec = init_vector;
  if (block_size > init_vector.size()) {
    throw std::invalid_argument("block_size");
  }
  _block_size = block_size;
}

template <int size_key> CFB<size_key>::~CFB<size_key>() {
  auto size = _init_vec.size();
  for (int i = 0; i < size; ++i) {
    _init_vec[i] = 0;
  }
}

template <int size_key>
void CFB<size_key>::encryption(const std::shared_ptr<std::istream> input,
                               std::shared_ptr<std::ostream> output) {

  char buffer[size_key];
  char out_buf[size_key];
  char block_buf[_block_size];
  memcpy(buffer, _init_vec.data(), size_key);

  while (input->read(block_buf, _block_size)) {
    this->encryptor->encryption(buffer, out_buf);
    for (int i = 0; i < _block_size; ++i) {
      block_buf[i] ^= out_buf[i];
    }
    std::move(buffer + size_key - _block_size, buffer + size_key, buffer);
    std::copy(block_buf, block_buf + _block_size,
              buffer + size_key - _block_size);
    output->write(block_buf, _block_size);
  }

  auto count = input->gcount();
  if (count != 0) {
    for (int i = count; i < _block_size; ++i) {
      block_buf[i] = 0;
    }
    this->encryptor->encryption(buffer, out_buf);
    for (int i = 0; i < _block_size; ++i) {
      block_buf[i] ^= out_buf[i];
    }
    output->write(block_buf, _block_size);
  }
  for (int i = 0; i < _block_size; ++i) {
    block_buf[i] = 0;
  }
  for (int i = 0; i < size_key; ++i) {
    buffer[i] = 0;
    out_buf[i] = 0;
  }
}

template <int size_key>
void CFB<size_key>::decryption(const std::shared_ptr<std::istream> input,
                               std::shared_ptr<std::ostream> output) {

  char buffer[size_key];
  char out_buf[size_key];
  char block_buf[_block_size];
  memcpy(buffer, _init_vec.data(), size_key);

  while (input->read(block_buf, _block_size)) {
    this->encryptor->encryption(buffer, out_buf);
    std::move(buffer + size_key - _block_size, buffer + size_key, buffer);
    std::copy(block_buf, block_buf + _block_size,
              buffer + size_key - _block_size);

    for (int i = 0; i < _block_size; ++i) {
      block_buf[i] ^= out_buf[i];
    }
    output->write(block_buf, _block_size);
  }

  auto count = input->gcount();
  if (count != 0) {
    for (int i = count; i < _block_size; ++i) {
      block_buf[i] = 0;
    }
    this->encryptor->encryption(buffer, out_buf);
    for (int i = 0; i < _block_size; ++i) {
      block_buf[i] ^= out_buf[i];
    }

    output->write(block_buf, _block_size);
  }
  for (int i = 0; i < _block_size; ++i) {
    block_buf[i] = 0;
  }
  for (int i = 0; i < size_key; ++i) {
    buffer[i] = 0;
    out_buf[i] = 0;
  }
}

#endif // !CfbcryptionModesECB_cpp
