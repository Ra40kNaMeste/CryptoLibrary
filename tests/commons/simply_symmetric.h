#include <isymmetric.h>
class SimplySymmetric : public ISymmetric<2> {
public:
  SimplySymmetric() : ISymmetric<2>({}) {}
  ~SimplySymmetric() {}

  void encryption(const char *input, char *output) override {
    output[0] = input[0] + 1;
    output[1] = input[1];
  }
  void decryption(const char *input, char *output) override {
    output[0] = input[0] - 1;
    output[1] = input[1];
  }
  int get_size_block() override { return 2; }
};
