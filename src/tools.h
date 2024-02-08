/*
  Define debug macros to facilitate debugging output. Adjust DEBUG flag as needed.
*/
#if DEBUG == 1
    #define debug(x) Serial.print(x)
    #define debugln(x) Serial.println(x)
#else
    #define debug(x)
    #define debugln(x)
#endif