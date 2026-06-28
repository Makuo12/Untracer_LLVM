wrap=$(pwd)

rm -rf output
mkdir -p output
clang++ -c libtracer.cpp -I include -o ./output/tracer.o

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

# 3. Copy the compiled binary back to your output directory
cp ./xpdf/pdftotext $wrap/output/pdftotext
cd $wrap

# 4. Setup basic blocks (gotten from __sanitizer_cov_pcs_init)
export WRITE_OUT="$wrap/output/text"
export COVERAGE="$wrap/output/coverage_log.txt"
./output/pdftotext > /dev/null 2>&1 || true