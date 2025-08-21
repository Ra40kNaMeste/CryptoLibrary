#ifndef SYMMETRIC_ISYMMETRIC_H
#define SYMMETRIC_ISYMMETRIC_H
#include <array>
#include <cstddef>
#include <istream>
#include <ostream>
template <int size_key> class ISymmetric {
public:
  ISymmetric(std::array<std::byte, size_key> key) { _key = key; }
  virtual ~ISymmetric() {}
  virtual void encryption(std::istream input, std::ostream output) = 0;
  virtual void decryption(std::istream input, std::ostream output) = 0;

protected:
  std::array<std::byte, size_key> _key;
};

#endif // !SYMMETRIC_ISYMMETRIC_H
