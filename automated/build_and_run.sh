cmake -S . -B build
cmake --build build

./build/kuro-sign "$@"