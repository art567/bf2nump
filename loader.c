/*================================================================================================================================
 * Name:
 *  BF2 Memory Patcher [NumP]
 *  [Battlefield 2 v1.50]
 *  - Public version to fix numPlayersNeededToStart
 *
 * Version:
 *  1.4.2 (Linux 32/64 bit) *Work In Progress*
 *  Date: 2024-09-10
 *
 * Short Desc:
 *  Patch gameserver's process memory without binary modification
 *  Applies in order to get patch to work while original binaries stays untouched
 *
 * Copyright (c) 2009-2021
 *  PlayBF2 Team, support@playbf2.com
 *  T~GAMER BF2 Team, tema567@tgamer.ru
 *  Artyom Shcherbakov aka Tema567
 *  http://github.com/art567
 *
 * All rights reserved.
================================================================================================================================*/
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <inttypes.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#define EXIT_SUCCESS 0
#define EXIT_FAILURE 1
#ifdef __LP64__
    #define byte_t uint8_t
    #define pbuf_t uint32_t
    #define addr_t uint64_t
    #define data_c unsigned char
    #define data_t unsigned char[]
    #define fmt_addr "%016lx"
    #define global uint32_t
#else
    #define byte_t uint8_t
    #define pbuf_t uint32_t
    #define addr_t uint32_t
    #define data_c unsigned char
    #define data_t unsigned char[]
    #define fmt_addr "%08x"
    #define global uint32_t
#endif
#define ms_default 0L
#define ms_playbf2 1L
#define ms_bf2hub  2L
struct bp { byte_t st; addr_t addr; pbuf_t buf; };
typedef struct bp bp;
static bp bpx[100] = {0};
char c_err[]="\033[1;31;40m";
char c_success[]="\033[1;32;40m";
char c_clear[]="\033[1;0m";
const long data_size = 4;
const long long_size = sizeof(long);

// =================================================== Settings =============================================================== //

global g_debug = 1;

// =================================================== Settings =============================================================== //

void print_regs(struct user_regs_struct regs)
{
#ifdef __LP64__
    if (g_debug)
    {
        printf("*DEBUG* Registers:");
        printf(" RIP = 0x%x", regs.rip);
        printf(" RAX = 0x%x", regs.rax);
        printf(" RBX = 0x%x", regs.rbx);
        printf(" RCX = 0x%x", regs.rcx);
        printf(" RDX = 0x%x", regs.rdx);
        printf(" RSI = 0x%x", regs.rsi);
        printf(" RDI = 0x%x", regs.rdi);
        printf(" RSP = 0x%x", regs.rsp);
        printf("\n");
    }
#else
    if (g_debug)
    {
        printf("*DEBUG* Registers:");
        printf(" EIP = 0x%x", regs.eip);
        printf(" EAX = 0x%x", regs.eax);
        printf(" EBX = 0x%x", regs.ebx);
        printf(" ECX = 0x%x", regs.ecx);
        printf(" EDX = 0x%x", regs.edx);
        printf(" ESI = 0x%x", regs.esi);
        printf(" EDI = 0x%x", regs.edi);
        printf(" ESP = 0x%x", regs.esp);
        printf("\n");
    }
#endif
}

bp set_break(pid_t pid, addr_t addr)
{
    char dbg_str[255];
    bp b = {0};
    b.addr = addr;
    b.buf = ptrace(PTRACE_PEEKDATA, pid, b.addr, 0);
    pbuf_t xbuf = (b.buf & ~0xff) | 0xcc;
    ptrace(PTRACE_POKEDATA, pid, b.addr, xbuf);
    b.st = 1;
    if (g_debug)
    {
        strcpy(dbg_str, "*DEBUG* <BREAK> Set at addr: 0x");
        strcat(dbg_str, fmt_addr);
        strcat(dbg_str, "\n");
        printf(dbg_str, b.addr);
    }
    return b;
}

bp rm_break(pid_t pid, bp b)
{
    char dbg_str[255];
    ptrace(PTRACE_POKEDATA, pid, b.addr, b.buf);
    b.st = 0;
    if (g_debug)
    {
        strcpy(dbg_str, "*DEBUG* <BREAK> Removed at addr: 0x");
        strcat(dbg_str, fmt_addr);
        strcat(dbg_str, "\n");
        printf(dbg_str, b.addr);
    }
    return b;
}

void set_rip(pid_t pid, addr_t addr)
{
    char dbg_str[255];
    struct user_regs_struct regs;

    if (g_debug)
    {
    #ifdef __LP64__
        strcpy(dbg_str, "*DEBUG* Set RIP register: 0x");
    #else
        strcpy(dbg_str, "*DEBUG* Set EIP register: 0x");
    #endif
        strcat(dbg_str, fmt_addr);
        strcat(dbg_str, "\n");
        printf(dbg_str, addr);
    }

    memset(&regs, 0, sizeof(regs));
    ptrace(PTRACE_GETREGS, pid, 0, &regs);
#ifdef __LP64__
    regs.rip = (addr_t)addr;
#else
    regs.eip = (addr_t)addr;
#endif
    ptrace(PTRACE_SETREGS, pid, 0, &regs);
}

int patch(pid_t pid, addr_t addr, data_c olddata[], data_c newdata[])
{
    char dbg_str[255];
    union u {long val; char chars[long_size];}data;
    long buf;
    if (g_debug)
    {
        strcpy(dbg_str, "*DEBUG* <PATCH> -> addr: 0x");
        strcat(dbg_str, fmt_addr);
        strcat(dbg_str, " \told:%02x%02x%02x%02x \tnew:%02x%02x%02x%02x\n");
        printf(dbg_str,
            (addr_t)addr,
            (byte_t)olddata[0], (byte_t)olddata[1], (byte_t)olddata[2], (byte_t)olddata[3],
            (byte_t)newdata[0], (byte_t)newdata[1], (byte_t)newdata[2], (byte_t)newdata[3]);
    }
    buf = ptrace(PTRACE_PEEKDATA, pid, addr, 0);
    data.val = buf;
    memcpy(data.chars, olddata, data_size);
    if (data.val == buf)
    {
        memcpy(data.chars, newdata, data_size);
        ptrace(PTRACE_POKEDATA, pid, addr, data.val);
        if (g_debug)
        {
            printf("%s", c_success);
            printf("*DEBUG* <PATCH> -----> SUCCESS!!!\n");
            printf("%s", c_clear);
        }
        return 0;
    }
    else
    {
        data.val = buf;
        if (g_debug)
        {
            printf("%s", c_err);
            strcpy(dbg_str, "*DEBUG* <PATCH> Err -> data is different!!! at addr: 0x");
            strcat(dbg_str, fmt_addr);
            strcat(dbg_str, ", mem: %02x%02x%02x%02x, req: %02x%02x%02x%02x\n");
            printf(dbg_str,
                (addr_t)addr,
                (byte_t)data.chars[0], (byte_t)data.chars[1], (byte_t)data.chars[2], (byte_t)data.chars[3], 
                (byte_t)olddata[0], (byte_t)olddata[1], (byte_t)olddata[2], (byte_t)olddata[3]);
            printf("%s", c_clear);
        }
        return 1;
    }
}

int fpatch(pid_t pid, addr_t addr, data_c newdata[])
{
    char dbg_str[255];
    union u {long val; char chars[long_size];}data;
    long buf;
    if (g_debug)
    {
        strcpy(dbg_str, "*DEBUG* <FPATCH> -> addr: 0x");
        strcat(dbg_str, fmt_addr);
        strcat(dbg_str, " \tnew:%02x%02x%02x%02x\n");
        printf(dbg_str,
            (addr_t)addr,
            (byte_t)newdata[0], (byte_t)newdata[1], (byte_t)newdata[2], (byte_t)newdata[3]);

    }
    buf = ptrace(PTRACE_PEEKDATA, pid, addr, 0);
    data.val = buf;
    memcpy(data.chars, newdata, data_size);
    ptrace(PTRACE_POKEDATA, pid, addr, data.val);
    if (g_debug)
    {
        printf("%s", c_success);
        printf("*DEBUG* <FPATCH> -----> SUCCESS!!!\n");
        printf("%s", c_clear);
    }
    return 0;
}

void child(char* target, char* cmdline)
{
    ptrace(PTRACE_TRACEME, 0, 0, 0);
    execl(target, target, cmdline, NULL);
    perror("execl");
}

void parent(pid_t chpid)
{
    int status;
    byte_t b0,b1,b2,b3;

    waitpid(0, &status, 0);

    //Uncomment if you want to use patch() by timer
    //+Comment ptrace(PTRACE_TRACEME, 0, 0, 0);
    //sleep(5);
    //ptrace(PTRACE_ATTACH, chpid, 0, 0);

    if (g_debug)
        printf("*DEBUG* Trace attached\n");

    ptrace(PTRACE_SETOPTIONS, chpid, 0, PTRACE_O_TRACESYSGOOD);

    if (g_debug)
    {
        printf("*DEBUG* Parent pid: %i\n", getpid());
        printf("*DEBUG* Child pid: %i\n", chpid);
    }

    kill(chpid, SIGSTOP);

    if (g_debug)
        printf("*DEBUG* Sent SIGSTOP\n");

    if (g_debug)
        printf("*DEBUG* Patching..\n");

// ======================================================== Patch Data ======================================================== //

    // == Begin of patch == //

#ifdef __LP64__

    // == Linux 64 bit == //

    // This bug usually appears on Linux x64 binary running bigger modifications
    // patch(chpid, (addr_t)0x006A2F03, (data_t){0xEB,0xD8,0x90,0x90}, (data_t){0xEB,0xE3,0x90,0x90}); // std::list<IObjectTemplate *>::remove(IObjectTemplate * const&) // Fixing annoying longest load times (for 64-bit only)

    // BF2VOIP vulnerability fix for BF2 v1.50 (refer to https://aluigi.org/adv/bf2voipz-adv.txt)
    // patch(chpid, (addr_t)0x004CC4AF, (data_t){0x0F,0x84,0xBC,0x00}, (data_t){0xE9,0xBD,0x00,0x00}); // dice::hfe::VoipServerConnection::HandlePacketChallengeString() // HandlePacketChallengeString fix
    // patch(chpid, (addr_t)0x004CC4B3, (data_t){0x00,0x00,0x4C,0x8D}, (data_t){0x00,0x90,0x4C,0x8D}); // dice::hfe::VoipServerConnection::HandlePacketChallengeString() // HandlePacketChallengeString fix

    // BF2NULL vulnerability fix for BF2 v1.50 (refer to https://aluigi.org/adv/bf2null-adv.txt)
    // patch(chpid, (addr_t)0x007D7613, (data_t){0x66,0x85,0xC0,0x75}, (data_t){0x90,0x90,0x90,0xEB}); // dice::hfe::io::NetServer::getPacketPtrFromRecvQueue()      // getPacketPtrFromRecvQueue fix

    // Allow stats to be handled even if you have a lot of players come in and came out in short period of time
    // patch(chpid, (addr_t)0x0045B8D9, (data_t){0x77,0x4C,0x48,0x8D}, (data_t){0x90,0x90,0x48,0x8D}); // dice::hfe::GameServer::addPersistenceConnection()          // Fix for limitation of 256 HTTP half-open connections

    // b2 = (byte_t)(g_squad_size - 1);
    // patch(chpid, (addr_t)0x004C3A56, (data_t){0x83,0xF8,0x05,0x7E}, (data_t){0x83,0xF8,b2,0x7E});   // dice::hfe::SquadManager::addToSquad()                      // Squad Size 6 => g_squad_size

    // b0 = (byte_t)(g_max_slots);
    // patch(chpid, (addr_t)0x004695B7, (data_t){0x83,0xF9,0x40,0x0F}, (data_t){0x83,0xF9,b0,0x0F});   // dice::hfe::ServerSettings::setMaxPlayers()                 // setMaxPlayers => b0 check
    // patch(chpid, (addr_t)0x004696B4, (data_t){0x40,0x00,0x00,0x00}, (data_t){b0,0x00,0x00,0x00});   // dice::hfe::ServerSettings::setMaxPlayers()                 // setMaxPlayers => b0 setter

    // Fix for sv.numPlayersNeededToStart numbers on your ranked server
    patch(chpid, (addr_t)0x00468807, (data_t){0x74,0x13,0xE8,0x72}, (data_t){0xEB,0x13,0xE8,0x72}); // dice::hfe::ServerSettings::getNumPlayersNeededToStart()       // jump always to retn
    patch(chpid, (addr_t)0x00468817, (data_t){0x8D,0x44,0x00,0x06}, (data_t){0x8D,0x44,0x00,0x00}); // dice::hfe::ServerSettings::getNumPlayersNeededToStart()       // change 8 players to 2

    // This is used for advanced player checks on masterserver backend
    // patch(chpid, (addr_t)0x00461812, (data_t){0x0F,0x85,0x49,0x02}, (data_t){0xE9,0x4A,0x02,0x00}); // dice::hfe::GameServer::handleClientInfo()                  // set jmp to verifyplayer.aspx (ignoring ranked state)
    // patch(chpid, (addr_t)0x00461816, (data_t){0x00,0x00,0x48,0x8D}, (data_t){0x00,0x90,0x48,0x8D}); // dice::hfe::GameServer::handleClientInfo()                  // set jmp to verifyplayer.aspx (ignoring ranked state)

#else

    // == Linux 32 bit == //

    // BF2VOIP vulnerability fix for BF2 v1.50 (refer to https://aluigi.org/adv/bf2voipz-adv.txt)
    // patch(chpid, (addr_t)0x08127619, (data_t){0x0F,0x84,0xE3,0x00}, (data_t){0xE9,0xE4,0x00,0x00}); // dice::hfe::VoipServerConnection::HandlePacketChallengeString() // HandlePacketChallengeString fix
    // patch(chpid, (addr_t)0x0812761D, (data_t){0x00,0x00,0x8D,0x85}, (data_t){0x00,0x90,0x8D,0x85}); // dice::hfe::VoipServerConnection::HandlePacketChallengeString() // HandlePacketChallengeString fix

    // BF2NULL vulnerability fix for BF2 v1.50 (refer to https://aluigi.org/adv/bf2null-adv.txt)
    // patch(chpid, (addr_t)0x0847CD1C, (data_t){0x66,0x85,0xD2,0x74}, (data_t){0x90,0x90,0x90,0x90}); // dice::hfe::io::NetServer::getPacketPtrFromRecvQueue()      // getPacketPtrFromRecvQueue fix
    // patch(chpid, (addr_t)0x0847CD20, (data_t){0x2C,0x8B,0x45,0x10}, (data_t){0x90,0x8B,0x45,0x10}); // dice::hfe::io::NetServer::getPacketPtrFromRecvQueue()      // getPacketPtrFromRecvQueue fix

    // Allow stats to be handled even if you have a lot of players come in and came out in short period of time
    // patch(chpid, (addr_t)0x080B62AB, (data_t){0x77,0x43,0x89,0x4C}, (data_t){0x90,0x90,0x89,0x4C}); // dice::hfe::GameServer::addPersistenceConnection()          // Fix for limitation of 256 HTTP half-open connections

    // b2 = (byte_t)(g_squad_size - 1);
    // patch(chpid, (addr_t)0x0811CCE9, (data_t){0x83,0xF8,0x05,0x0F}, (data_t){0x83,0xF8,b2,0x0F});   // dice::hfe::SquadManager::addToSquad                        // Squad Size 6 => g_squad_size

    // b1 = (byte_t)(g_max_slots);
    // b3 = (byte_t)(g_max_slots + 1);
    // patch(chpid, (addr_t)0x080BB78F, (data_t){0x10,0x83,0xFA,0x41}, (data_t){0x10,0x83,0xFA,b3});   // dice::hfe::ServerSettings::setMaxPlayers()                 // setMaxPlayers => b3 check
    // patch(chpid, (addr_t)0x080BB793, (data_t){0xB8,0x40,0x00,0x00}, (data_t){0xB8,b1,0x00,0x00});   // dice::hfe::ServerSettings::setMaxPlayers()                 // setMaxPlayers => b1 setter

    // Fix for sv.numPlayersNeededToStart numbers on your ranked server
    patch(chpid, (addr_t)0x080BC200, (data_t){0x74,0x1E,0x89,0x04}, (data_t){0xEB,0x1E,0x89,0x04}); // dice::hfe::ServerSettings::getNumPlayersNeededToStart()       // jump always to retn
    patch(chpid, (addr_t)0x080BC213, (data_t){0x8D,0x44,0x00,0x06}, (data_t){0x8D,0x44,0x00,0x00}); // dice::hfe::ServerSettings::getNumPlayersNeededToStart()       // change 8 players to 2

    // This is used for advanced player checks on masterserver backend
    // patch(chpid, (addr_t)0x080AAE0F, (data_t){0x0F,0x85,0x74,0x08}, (data_t){0xE9,0x75,0x08,0x00}); // dice::hfe::GameServer::handleClientInfo()                  // set jmp to verifyplayer.aspx (ignoring ranked state)
    // patch(chpid, (addr_t)0x080AAE13, (data_t){0x00,0x00,0x89,0x7C}, (data_t){0x00,0x90,0x89,0x7C}); // dice::hfe::GameServer::handleClientInfo()                  // set jmp to verifyplayer.aspx (ignoring ranked state)

#endif

    // == End of patch == //

// ======================================================== Patch Data ======================================================== //

    if (g_debug)
        printf("*DEBUG* Patch executed!\n");

    kill(chpid, SIGCONT);

    if (g_debug)
        printf("*DEBUG* Sent SIGCONT\n");

    ptrace(PTRACE_DETACH, chpid, 0, 0);

    if (g_debug)
        printf("*DEBUG* Trace detached\n");

    waitpid(0, &status, 0);

    if (g_debug)
    {
        if (WIFEXITED(status))
            printf("*DEBUG* Child terminated normally with exit code #%i\n", WEXITSTATUS(status));
        if (WIFSIGNALED(status))
            printf("*DEBUG* Child was terminated by signal #%i\n", WTERMSIG(status));
        if (WCOREDUMP(status))
            printf("*DEBUG* Child dumped core\n");
        if (WIFSTOPPED(status))
            printf("*DEBUG* Child was stopped by signal #%i\n", WSTOPSIG(status));
    }
}

int main(int argc, char *argv[])
{
    char cmdline[255];
    char target[255];
    int count;

    printf("%s\n%s", c_success, c_clear);
    printf("%s>>> Battlefield 2 v1.50 Loader [NumP]\n%s", c_success, c_clear);
    printf("%s> ($a) Tema567   - tema567@playbf2.com\n%s", c_success, c_clear);
    printf("%s> ($c) 2020-2024 - PlayBF2\n%s", c_success, c_clear);

    if (argc < 2)
    {
        printf("\n%sThere is no argument(s) supplied!%s\n", c_err, c_clear);
        printf("%sUsage: %s /path/to/server/bin/mach/bf2 [args]%s\n\n", c_err, argv[0], c_clear);
        return EXIT_SUCCESS;
    }

    strcpy(cmdline, "");
    strcpy(target, argv[1]);

    if (argc > 2)
    {
        for (count = 2; count < argc; count++)
        {

            if (count > 2)
            {
                strcat(cmdline, " ");
            }
            strcat(cmdline, argv[count]);
        }
    }

    if (g_debug)
    {
        printf("*DEBUG* Target cmdline = %s %s\n", target, cmdline);
    }

    pid_t chpid = fork();

    if (chpid)
    {
        parent(chpid);
    }
    else
    {
        child(target, cmdline);
    }

    return EXIT_SUCCESS;
}
