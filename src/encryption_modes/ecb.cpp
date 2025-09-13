#ifndef ENCRYPTIONMODES_ECB_CPP
#define ENCRYPTIONMODES_ECB_CPP
#include <ecb.h>

template <int size_key>
void ECB<size_key>::encryption(std::shared_ptr<std::istream> input,
                               std::shared_ptr<std::ostream> output) {
  auto block_size = this->encryptor->get_size_block();
  char buffer[block_size];
  char out_buf[block_size];
  while (input.get(buffer, block_size)) {
    this->encryptor.encryption(buffer, out_buf);
    output->write(out_buf, block_size);
  }
  for (int i = 0; i < block_size; ++i) {
    buffer[i] = 0;
    out_buf[i] = 0;
  }
}

template <int size_key>
void ECB<size_key>::decryption(std::shared_ptr<std::istream> input,
                               std::shared_ptr<std::ostream> output) {
  // this->encryptor.decryption(input, output);
}

#endif // !EncryptionModesECB_cpp
