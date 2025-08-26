#ifndef CORE_TLS_UTILS_H
#define CORE_TLS_UTILS_H


#define EXPECT_OK(s, stmt) \
    do { \
        if ((s = stmt) != "") goto error; \
    } while (0)

#define EXPECT_RECEIVE(s, a, handler) \
    do { \
        s = this->alert(2, 0); \
        a = rw.read(); \
        if (!a || (s = handler(std::move(*a))) != "") goto error; \
    } while (0)


#endif
