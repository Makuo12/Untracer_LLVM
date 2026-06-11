clang++ -c libtracer.cpp -o ./output/tracer.o
wrap="/home/makuo12/Documents/forte-research/learn_wrap"

echo "Building xpdf with custom coverage tracer..."
cd $wrap/xpdf-4.06_2
rm -rf build
mkdir -p build && cd build

# 1. Define the coverage flags we want applied to EVERY source file
COVERAGE_FLAGS="-fsanitize-coverage=trace-pc-guard,pc-table -fno-pie"

cmake -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_C_COMPILER=clang \
        -DCMAKE_CXX_COMPILER=clang++ \
        -DCMAKE_TRY_COMPILE_TARGET_TYPE=STATIC_LIBRARY \
        -DCMAKE_C_FLAGS="$COVERAGE_FLAGS" \
        -DCMAKE_CXX_FLAGS="$COVERAGE_FLAGS" \
        -DCMAKE_EXE_LINKER_FLAGS="$wrap/output/tracer.o -no-pie" \
        ../

# 2. Build the pdftotext utility
make pdftotext

# 3. Copy the compiled binary back to your output directory (fixed typo)
cp ./xpdf/pdftotext $wrap/output/pdftotext
cd ../..