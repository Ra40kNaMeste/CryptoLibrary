#ifndef SYMMETRIC_FEISTELNETWORK_H
#define SYMMETRIC_FEISTELNETWORK_H
#include <array>
#include <isymmetric.h>
template <int size_block, int size_key>
class FeistelNetwork : public ISymmetric<size_key> {
public:
  FeistelNetwork(std::array<std::byte, size_key> key);
  ~FeistelNetwork();

protected:
};
#endif // !FEISTELNETWORK_H
