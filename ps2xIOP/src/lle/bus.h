#pragma once

#include <cstdint>
#include <cstring>
#include <vector>

namespace ps2x::iop::lle
{
    // Hardware registers behind 0x1F801000 and the SPU2 window.
    class IoDevice
    {
    public:
        virtual ~IoDevice() = default;
        virtual uint32_t ioRead(uint32_t physical, unsigned bytes) = 0;
        virtual void ioWrite(uint32_t physical, uint32_t value, unsigned bytes) = 0;
    };

    // The IOP's physical address space: 2 MiB of RAM (mirrored through the
    // first 8 MiB), the 1 KiB scratchpad and memory-mapped hardware.
    class Bus
    {
    public:
        static constexpr uint32_t kRamBytes = 2u << 20;

        explicit Bus(IoDevice &io) : m_io(io), m_ram(kRamBytes, 0u), m_scratchpad(1024u, 0u) {}

        uint8_t *ram() { return m_ram.data(); }
        const uint8_t *ram() const { return m_ram.data(); }

        // Instruction fetches bypass the read hook: they flood it and are not what a polling loop spins on.
        uint32_t fetch(uint32_t address)
        {
            const uint32_t physical = address & 0x1FFFFFFFu;
            uint32_t value = 0;
            if (physical < 0x00800000u)
                std::memcpy(&value, &m_ram[physical & (kRamBytes - 4u)], 4);
            else if ((physical & ~0x3FFu) == 0x1F800000u)
                std::memcpy(&value, &m_scratchpad[physical & (0x400u - 4u)], 4);
            else
                value = m_io.ioRead(physical, 4);
            return value;
        }

        uint8_t read8(uint32_t address) { return static_cast<uint8_t>(read<1>(address)); }
        uint16_t read16(uint32_t address) { return static_cast<uint16_t>(read<2>(address)); }
        uint32_t read32(uint32_t address) { return read<4>(address); }
        void write8(uint32_t address, uint8_t value) { write<1>(address, value); }
        void write16(uint32_t address, uint16_t value) { write<2>(address, value); }
        void write32(uint32_t address, uint32_t value) { write<4>(address, value); }

        // Debug hook: called after every load with the address and the value it returned. Null in normal runs.
        using ReadHook = void (*)(void *context, uint32_t address, unsigned bytes, uint32_t value);
        ReadHook readHook = nullptr;
        void *readHookContext = nullptr;

    private:
        template <unsigned Bytes>
        uint32_t read(uint32_t address)
        {
            const uint32_t physical = address & 0x1FFFFFFFu;
            uint32_t value = 0;
            if (physical < 0x00800000u)
                std::memcpy(&value, &m_ram[physical & (kRamBytes - Bytes)], Bytes);
            else if ((physical & ~0x3FFu) == 0x1F800000u)
                std::memcpy(&value, &m_scratchpad[physical & (0x400u - Bytes)], Bytes);
            else
                value = m_io.ioRead(physical, Bytes);
            if (readHook != nullptr)
                readHook(readHookContext, address, Bytes, value);
            return value;
        }

        template <unsigned Bytes>
        void write(uint32_t address, uint32_t value)
        {
            const uint32_t physical = address & 0x1FFFFFFFu;
            if (physical < 0x00800000u)
                std::memcpy(&m_ram[physical & (kRamBytes - Bytes)], &value, Bytes);
            else if ((physical & ~0x3FFu) == 0x1F800000u)
                std::memcpy(&m_scratchpad[physical & (0x400u - Bytes)], &value, Bytes);
            else
                m_io.ioWrite(physical, value, Bytes);
        }

        IoDevice &m_io;
        std::vector<uint8_t> m_ram;
        std::vector<uint8_t> m_scratchpad;
    };
}
