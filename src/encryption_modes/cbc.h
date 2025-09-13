#ifndef CBCCRYPTIONMODES_ECB_H
#define CBCCRYPTIONMODES_ECB_H
#include "isymmetric.h"
#include <array>
#include <cstddef>
#include <encryption_mode_base.h>
#include <istream>
#include <memory>
#include <ostream>
#include <vector>
template <int size_key> class CBC : public EncryptionModeBase<size_key> {
public:
  CBC(std::shared_ptr<ISymmetric<size_key>> encryptor)
      : EncryptionModeBase<size_key>(encryptor) {}
  void init(std::vector<std::byte> init_vector);
  ~CBC<size_key>() {}

  void encryption(std::shared_ptr<std::istream> input,
                  std::shared_ptr<std::ostream> output) override;
  void decryption(std::shared_ptr<std::istream> input,
                  std::shared_ptr<std::ostream> output) override;

private:
  std::vector<std::byte> _init_vec;
};
#include "cbc.cpp"
#endif // !CBCCRYPTIONMODES_ECB_H
