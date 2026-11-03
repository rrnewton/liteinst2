/* Shared exact original decimal environment parser. */
static uint64_t pgc_environment_number(const char *key) {
    const char *const *env=bridge_environment();const char *value=0;
    for(size_t i=0;env[i];i++) {
        size_t j=0;while(key[j] && key[j]==env[i][j])j++;
        if(!key[j]){checked(!value,3390,1);value=env[i]+j;}
    }
    checked(value && *value && *value!='0',3390,2);uint64_t n=0;
    while(*value){checked(*value>='0' && *value<='9' && n<=(UINT64_MAX-(*value-'0'))/10,3390,3);
        n=n*10+(unsigned)(*value++-'0');}
    return n;
}
