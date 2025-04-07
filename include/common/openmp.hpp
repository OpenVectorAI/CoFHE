#ifndef CoFHE_OPENMP_HPP_INCLUDED
#define CoFHE_OPENMP_HPP_INCLUDED

#ifdef OPENMP
#include <omp.h>
#define CoFHE_PARALLEL_FOR_STATIC_SCHEDULE _Pragma("omp parallel for schedule(static)")
#define CoFHE_PARALLEL_FOR_STATIC_SCHEDULE_COLLAPSE_2 _Pragma("omp parallel for schedule(static) collapse(2)")
#else
#define CoFHE_PARALLEL_FOR_STATIC_SCHEDULE
#define CoFHE_PARALLEL_FOR_STATIC_SCHEDULE_COLLAPSE_2
#endif

#endif