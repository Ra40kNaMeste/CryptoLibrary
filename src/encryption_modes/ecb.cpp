#ifndef ENCRYPTIONMODES_ECB_CPP
#define ENCRYPTIONMODES_ECB_CPP
#include <ecb.h>

template <int size_key>
void ECB<size_key>::encryption(std::shared_ptr<std::istream> input,
                               std::shared_ptr<std::ostream> output) {
  this->encryptor.encription(input, output);
}

template <int size_key>
void ECB<size_key>::decryption(std::shared_ptr<std::istream> input,
                               std::shared_ptr<std::ostream> output) {
  this->encryptor.decryption(input, output);
}

#endif // !EncryptionModesECB_cpp
