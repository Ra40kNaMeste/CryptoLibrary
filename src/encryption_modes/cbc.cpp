#ifndef CBCCRYPTIONMODES_ECB_CPP
#define CBCCRYPTIONMODES_ECB_CPP
#include <cbc.h>
#include <cstring>
#include <filesystem>
#include <ios>
#include <stdexcept>
#include <vector>

template <int size_key>
void CBC<size_key>::init(const std::vector<char> &init_vector) {
  if (init_vector.size() != this->encryptor->get_size_block()) {
    throw std::invalid_argument("init_vector");
  }
  this->_init_vec = init_vector;
}

template <int size_key> CBC<size_key>::~CBC<size_key>() {
  auto size = _init_vec.size();
  for (int i = 0; i < size; ++i) {
    _init_vec[i] = 0;
  }
}

template <int size_key>
void CBC<size_key>::encryption(const std::shared_ptr<std::istream> input,
                               std::shared_ptr<std::ostream> output) {
  auto block_size = this->encryptor->get_size_block();
  char buffer[block_size];
  char pre_out_buf[block_size];
  memcpy(pre_out_buf, _init_vec.data(), block_size);

  char *pre_out_buf_ptr = pre_out_buf;
  char out_buf[block_size];

  while (input->read(buffer, block_size)) {
    for (int i = 0; i < block_size; ++i) {
      buffer[i] ^= pre_out_buf_ptr[i];
    }
    this->encryptor->encryption(buffer, out_buf);
    output->write(out_buf, block_size);
    pre_out_buf_ptr = out_buf;
  }

  auto count = input->gcount();
  if (count != 0) {
    for (int i = count; i < block_size; ++i) {
      buffer[i] = 0;
    }
    for (int i = 0; i < block_size; ++i) {
      buffer[i] ^= pre_out_buf_ptr[i];
    }
    this->encryptor->encryption(buffer, out_buf);
    output->write(out_buf, block_size);
  }

  for (int i = 0; i < block_size; ++i) {
    buffer[i] = 0;
    out_buf[i] = 0;
    pre_out_buf[i] = 0;
  }
}

template <int size_key>
void CBC<size_key>::decryption(const std::shared_ptr<std::istream> input,
                               std::shared_ptr<std::ostream> output) {
  auto block_size = this->encryptor->get_size_block();

  // чтение всего потока
  input->seekg(0, std::ios::end);
  std::streamsize size = input->tellg(); // размер потока
  input->seekg(0, std::ios::beg);
  if (size == 0 || size % block_size != 0) {
    throw std::invalid_argument("input");
  }
  char buffer[size];
  if (!input->read(buffer, size)) {
    return;
  }

  char out_buf[size];
  for (std::streamsize i = size - 2 * block_size; i >= 0; i -= block_size) {

    this->encryptor->decryption(buffer + i + block_size,
                                out_buf + i + block_size);
    for (int j = 0; j < block_size; ++j) {
      out_buf[i + block_size + j] ^= buffer[i + j];
    }
  }
  this->encryptor->decryption(buffer, out_buf);
  for (int j = 0; j < block_size; ++j) {
    out_buf[j] ^= _init_vec[j];
  }
  output->write(out_buf, size);

  for (int i = 0; i < size; ++i) {
    buffer[i] = 0;
    out_buf[i] = 0;
  }
}

#endif // !CbccryptionModesECB_cpp
