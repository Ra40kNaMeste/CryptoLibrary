#ifndef SYMMETRIC_FESTELNETWORK
#define SYMMETRIC_FESTELNETWORK
#include <cstring>
#include <feistel_network.h>
#include <functional>
#include <iostream>
#include <isymmetric.h>
#include <memory>
template <int size_block, int count_block, int size_key, int size_round_key>
FeistelNetwork<size_block, count_block, size_key, size_round_key>::
    FeistelNetwork(std::array<std::byte, size_key> key, int rounds)
    : ISymmetric<size_key>(key) {
  this->_rounds = rounds;
}

template <int size_block, int count_block, int size_key, int size_round_key>
FeistelNetwork<size_block, count_block, size_key,
               size_round_key>::~FeistelNetwork() {}

template <int size_block, int count_block, int size_key, int size_round_key>
void FeistelNetwork<size_block, count_block, size_key, size_round_key>::
    encryption(std::shared_ptr<std::istream> input,
               std::shared_ptr<std::ostream> output) {
  this->cryption(input, output, [](int i) { return i; });
}

template <int size_block, int count_block, int size_key, int size_round_key>
void FeistelNetwork<size_block, count_block, size_key, size_round_key>::
    decryption(std::shared_ptr<std::istream> input,
               std::shared_ptr<std::ostream> output) {
  this->cryption(input, output,
                 [this](int i) { return this->_rounds - i - 1; });
}

template <int size_block, int count_block, int size_key, int size_round_key>
void FeistelNetwork<size_block, count_block, size_key, size_round_key>::
    cryption(std::shared_ptr<std::istream> input,
             std::shared_ptr<std::ostream> output,
             std::function<int(int)> get_i) {
  char *buf = new char[size_block * count_block];
  char *crypt_buf = new char[size_block * count_block];
  while (input->read(buf, size_block * count_block)) {
    int i = 0;
    for (i = 0; i < this->_rounds; ++i) {
      auto key = this->get_round_key(get_i(i));
      auto adding = this->f(buf + (i % count_block) * size_block,
                            reinterpret_cast<char *>(key.data()));
      for (int j = 0; j < count_block; ++j) {
        if (j != i % count_block) {
          this->append(buf + j * size_block,
                       reinterpret_cast<char *>(adding.data()));
        }
      }
    }
    i %= count_block;
    std::memcpy(crypt_buf, buf + i * size_block,
                (count_block - i) * size_block);
    std::memcpy(crypt_buf + (count_block - i) * size_block, buf,
                i * size_block);
    output->write(crypt_buf, size_block * count_block);
  }
  delete[] buf;
  delete[] crypt_buf;
}

#endif // !SYMMETRIC_FESTELNETWORK
