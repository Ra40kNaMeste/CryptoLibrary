#pragma once
#include "isymmetric.h"
#include <istream>
#include <memory>
#include <ostream>
template <int size_key> class EncryptionModeBase {
public:
  EncryptionModeBase(std::shared_ptr<ISymmetric<size_key>> encryptor) {
    this->encryptor = encryptor;
  }
  virtual ~EncryptionModeBase() {}

  virtual void encryption(const std::shared_ptr<std::istream> input,
                          std::shared_ptr<std::ostream> output) = 0;
  virtual void decryption(const std::shared_ptr<std::istream> input,
                          std::shared_ptr<std::ostream> output) = 0;

protected:
  std::shared_ptr<ISymmetric<size_key>> encryptor;
};
