#ifndef ENCRYPTIONMODES_ECB_CPP
#define ENCRYPTIONMODES_ECB_CPP
#include <ecb.h>

template <int size_key>
void ECB<size_key>::encryption(const std::shared_ptr<std::istream> input,
                               std::shared_ptr<std::ostream> output) {
  auto block_size = this->encryptor->get_size_block();
  char buffer[block_size];
  char out_buf[block_size];
  int i = 0;
  while (input->read(buffer, block_size) && i < 5) {
    this->encryptor->encryption(buffer, out_buf);
    output->write(out_buf, block_size);
    i++;
  }

  auto count = input->gcount();
  if (count != 0) {
    for (int i = count; i < block_size; ++i) {
      buffer[i] = 0;
    }
    this->encryptor->encryption(buffer, out_buf);
    output->write(out_buf, count);
  }

  for (int i = 0; i < block_size; ++i) {
    buffer[i] = 0;
    out_buf[i] = 0;
  }
}

template <int size_key>
void ECB<size_key>::decryption(const std::shared_ptr<std::istream> input,
                               std::shared_ptr<std::ostream> output) {
  auto block_size = this->encryptor->get_size_block();
  char buffer[block_size];
  char out_buf[block_size];
  while (input->read(buffer, block_size)) {
    this->encryptor->decryption(buffer, out_buf);
    output->write(out_buf, block_size);
  }
  auto count = input->gcount();
  if (count != 0) {
    for (int i = count; i < block_size; ++i) {
      buffer[i] = 0;
    }
    this->encryptor->decryption(buffer, out_buf);
    output->write(out_buf, count);
  }
  for (int i = 0; i < block_size; ++i) {
    buffer[i] = 0;
    out_buf[i] = 0;
  }
}

#endif // !EncryptionModesECB_cpp
