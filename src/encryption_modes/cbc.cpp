#ifndef CBCCRYPTIONMODES_ECB_CPP
#define CBCCRYPTIONMODES_ECB_CPP
#include <cbc.h>
#include <cstring>
#include <filesystem>
#include <stdexcept>
#include <vector>

template <int size_key>
void CBC<size_key>::init(std::vector<std::byte> init_vector) {
  if (init_vector.size() != this->encryptor->get_size_block()) {
    throw std::invalid_argument("init_vector");
  }
  this->_init_vec = init_vector;
}

template <int size_key>
void CBC<size_key>::encryption(std::shared_ptr<std::istream> input,
                               std::shared_ptr<std::ostream> output) {
  auto block_size = this->encryptor->get_size_block();
  char buffer[block_size];
  char pre_out_buf[block_size];
  memcpy(pre_out_buf, _init_vec.begin(), block_size);

  char *pre_out_buf_ptr = pre_out_buf;
  char out_buf[block_size];

  while (input.get(buffer, block_size)) {
    this->_symmetric.encryption(buffer, out_buf);
    for (int i = 0; i < block_size; ++i) {
      out_buf[i] ^= pre_out_buf_ptr[i];
    }
    pre_out_buf_ptr = pre_out_buf;
    output->write(out_buf, block_size);
  }
  for (int i = 0; i < block_size; ++i) {
    buffer[i] = 0;
    out_buf[i] = 0;
    pre_out_buf[i] = 0;
  }
}

template <int size_key>
void CBC<size_key>::decryption(std::shared_ptr<std::istream> input,
                               std::shared_ptr<std::ostream> output) {
  // this->encryptor.decryption(input, output);
}

#endif // !CbccryptionModesECB_cpp
