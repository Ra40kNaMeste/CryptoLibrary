#pragma once
#ifndef CBCCRYPTIONMODES_ECB_H
#define CBCCRYPTIONMODES_ECB_H
#include "isymmetric.h"
#include <encryption_mode_base.h>
#include <istream>
#include <memory>
#include <ostream>
#include <vector>

// Сцепление блоков шифром. Кодирует в realtime, раскодирует - весь текст
// После создания - инициализировать методом init
template <int size_key> class CBC : public EncryptionModeBase<size_key> {
public:
  CBC(std::shared_ptr<ISymmetric<size_key>> encryptor)
      : EncryptionModeBase<size_key>(encryptor) {}
  // передавать ключ равный размеру блока кодера
  void init(const std::vector<char> &init_vector);
  ~CBC<size_key>();
  // кодирует в realtime. Заполняет конец 0, пока не будет кратно размеру блока
  // кодера
  void encryption(const std::shared_ptr<std::istream> input,
                  std::shared_ptr<std::ostream> output) override;
  // раскодирует текст. Только текст, размер которого > 0 и кратен размеру блока
  // кодера
  void decryption(const std::shared_ptr<std::istream> input,
                  std::shared_ptr<std::ostream> output) override;

private:
  std::vector<char> _init_vec;
};
#include "cbc.cpp"
#endif // !CBCCRYPTIONMODES_ECB_H
