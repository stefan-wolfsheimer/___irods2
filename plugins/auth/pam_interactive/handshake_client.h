#pragma once
#include <string>


namespace PamHandshake
{
#ifdef RODS_SERVER  
  class DataBuffer
  {
  public:
    DataBuffer(const std::string & _buffer);
    bool init(void *curl) const;
    const std::string & getResult() const;

  private:
    static std::size_t read(void *ptr, size_t size, size_t nmemb, void *data);
    static std::size_t write(void *contents, size_t size, size_t nmemb, void *data);

    std::string buffer;
    std::string result;
    size_t uploaded;
  };
#endif
}
