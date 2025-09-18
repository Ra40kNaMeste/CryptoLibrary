#ifndef ENCRYPTIONMODES_ECB_H
#define ENCRYPTIONMODES_ECB_H
#include "isymmetric.h"
#include <encryption_mode_base.h>
#include <istream>
#include <memory>
#include <ostream>

//"электронная кодовая книга. Кодирует и раскодирует в realtime"
template <int size_key> class ECB : public EncryptionModeBase<size_key> {
public:
  ECB(std::shared_ptr<ISymmetric<size_key>> encryptor)
      : EncryptionModeBase<size_key>(encryptor) {}
  ~ECB<size_key>() {}

  void encryption(const std::shared_ptr<std::istream> input,
                  std::shared_ptr<std::ostream> output) override;
  void decryption(const std::shared_ptr<std::istream> input,
                  std::shared_ptr<std::ostream> output) override;
};
#include "ecb.cpp"
#endif // !ENCRYPTIONMODES_ECB_H
