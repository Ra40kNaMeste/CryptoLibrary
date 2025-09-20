#pragma once
#include <array>
#ifndef CFBCRYPTIONMODES_ECB_H
#define CFBCRYPTIONMODES_ECB_H
#include "isymmetric.h"
#include <encryption_mode_base.h>
#include <istream>
#include <memory>
#include <ostream>
#include <vector>

template <int size_key> class CFB : public EncryptionModeBase<size_key> {
public:
  CFB(std::shared_ptr<ISymmetric<size_key>> encryptor)
      : EncryptionModeBase<size_key>(encryptor) {}
  // передавать ключ равный размеру блока ключа кодера
  // block_size - размер блока кодирования < размера блока ключа
  void init(const std::vector<char> &init_vector, int block_size);
  ~CFB<size_key>();
  // кодирует в realtime. Заполняет конец 0, пока не будет кратно размеру
  // блока кодера
  void encryption(const std::shared_ptr<std::istream> input,
                  std::shared_ptr<std::ostream> output) override;
  // раскодирует в realtime текст. Дополняет до блока нулями
  void decryption(const std::shared_ptr<std::istream> input,
                  std::shared_ptr<std::ostream> output) override;

private:
  std::vector<char> _init_vec;
  int _block_size;
};
#include "cfb.cpp"
#endif // !CFBCRYPTIONMODES_ECB_H
