/* shellen native module */

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <limits.h>

#include <sys/mman.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <Python.h>

#define PROT_RWX (PROT_READ | PROT_WRITE | PROT_EXEC)

static size_t
shellcode_buf_aligned_len(size_t len)
{
    /* Set up the pages like so - that way, if (when) we overrun the buffer,
     * we get a segfault and don't start executing into no-man's land.
     * +--------------+--------------+-----+----------------+
     * | page 1 (rwx) | page 2 (rwx) | ... | page n+1 (---) |
     * +--------------+--------------+-----+----------------+
     */
    int pagesize = getpagesize();
    size_t pages = (pagesize + len - 1) / pagesize;
    return (pages + 1) * pagesize;
}

static void *
allocate_shellcode_buf(size_t len)
{
    int pagesize = getpagesize();
    size_t bytes = shellcode_buf_aligned_len(len);
    size_t non_guard_bytes = bytes - pagesize;
    void *ptr = NULL;
    
    if (posix_memalign(&ptr, pagesize, bytes) != 0) {
        return NULL;
    }

    // Clear out the allocated memory
    memset(ptr, 0, bytes);

    // Set up the pages
    if (mprotect(ptr, non_guard_bytes, PROT_RWX) != 0 ||
        mprotect(ptr + non_guard_bytes, pagesize, PROT_NONE) != 0) {
        perror("mprotect");
        abort();
    } else {
        return ptr;
    }
}

static void
free_shellcode_buf(void *ptr, size_t len)
{
    size_t bytes = shellcode_buf_aligned_len(len);

    // Wow! We made it this far. Reset the protection.
    if (mprotect(ptr, bytes, PROT_READ | PROT_WRITE) != 0) {
        perror("mprotect");
        abort();
    } else {
        free(ptr);
    }
}

typedef int (*sh_fn_t)(void);

static int
geronimo(const void *buf)
{
    sh_fn_t fn = (sh_fn_t) buf;

    // Good luck!
    return fn();
}

static int
run(const void *buf, size_t len)
{
    void *shellcode = allocate_shellcode_buf(len);
    if (shellcode == NULL) {
        return -1; // TODO: add meaningful error codes
    }

    memcpy(shellcode, buf, len);
    int ret = geronimo(shellcode);
    free_shellcode_buf(shellcode, len);
    return ret;
}

static bool
fork_and_run(const void *buf, size_t len, int *status)
{
    pid_t child = fork();
    if (child == -1) {
        // Error forking
        return false;
    } else if (child == 0) {
        /* TODO: trap signals; wait for a debugger to attach; etc */
        exit(run(buf, len));
    } else {
        int result = 0;
        if (waitpid(child, &result, 0) != child) {
            // Error waiting
            return false;
        } else if (WIFEXITED(result)) {
            // Process exited; return value is >= 0.
            *status = WEXITSTATUS(result);
            return true;
        } else if (WIFSIGNALED(result)) {
            // Process signaled, return value is the negative signal number.
            *status = -WTERMSIG(result);
            return true;
        } else {
            // Not exited or signaled?
            return false;
        }
    }
}

const char sh_native_run_docs[] = "Executes arbitrary machine code. " \
                                  "Please do not call this if you don't " \
                                  "completely trust the code you're running.";

/* Runs completely arbitrary machine instructions.
 * Example: shellen_native.run(b'\x90' * 1000)
 */
PyObject *
sh_native_run(PyObject *self, PyObject *args)
{
    Py_buffer buffer;
    if (!PyArg_ParseTuple(args, "y*", &buffer)) {
        return NULL;
    }

    int ret = 0;
    if (!fork_and_run(buffer.buf, buffer.len, &ret)) {
        return NULL;
    } else {
        return Py_BuildValue("i", ret);
    }
}

/* Initialize the module. */
PyMODINIT_FUNC
PyInit_shellen_native(void)
{
    static struct PyMethodDef shellen_methods[] = {
        {"run", sh_native_run, METH_VARARGS, sh_native_run_docs},
        {NULL}
    };
    static struct PyModuleDef module = {
        PyModuleDef_HEAD_INIT,
        "shellen_native",
        "Native methods for Shellen",
        -1,
        shellen_methods
    };
    return PyModule_Create(&module);
}
