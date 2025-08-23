#ifndef SYMMETRIC_FEISTELNETWORK_H
#define SYMMETRIC_FEISTELNETWORK_H
#include <array>
#include <functional>
#include <istream>
#include <isymmetric.h>
#include <memory>
#include <ostream>
template <int size_block, int count_block, int size_key, int size_round_key>
class FeistelNetwork : public ISymmetric<size_key> {
public:
  FeistelNetwork(std::array<std::byte, size_key> key, int rounds);
  ~FeistelNetwork();
  void encryption(std::shared_ptr<std::istream> input,
                  std::shared_ptr<std::ostream> output) override;
  void decryption(std::shared_ptr<std::istream> input,
                  std::shared_ptr<std::ostream> output) override;

protected:
  virtual std::array<std::byte, size_round_key> get_round_key(int i) = 0;
  virtual std::array<std::byte, size_block> f(const char *first,
                                              const char *key) = 0;

  virtual void append(char *target, const char *value) = 0;

private:
  void cryption(std::shared_ptr<std::istream> input,
                std::shared_ptr<std::ostream> output,
                std::function<int(int)> get_i);
  int _rounds;
};
#include "feistel_network.cpp"
#endif // !FEISTELNETWORK_H
