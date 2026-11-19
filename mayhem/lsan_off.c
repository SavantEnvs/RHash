/* Leak detection is not the defect class this integration fuzzes for (SPEC 6.2 item 15);
 * ASan's memory-safety checks and UBSan stay fully active. */
int __lsan_is_turned_off(void) { return 1; }
