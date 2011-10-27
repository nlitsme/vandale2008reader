#include <stdio.h>
#include "crypto/hash.h"
#include "util/ReadWriter.h"
#include "util/rw/MmapReader.h"
#include "compress/zlib.h"
#include <array>
#include <set>
#include <map>

std::map<std::string,std::string> keymap= {
    { "dn", "7F54B1D3-4653-4D59-B9E8-2AB8A405A5EB" },
    { "en", "6F6820A6-81A3-49A8-BAAA-10EFFC00E9BC" },
    { "fn", "97B57BD2-767B-41F1-ABAB-DD7C7B3F1F46" },
    { "nd", "8AF90274-27A3-49D2-84EC-8970FB500741" },
    { "ne", "99FC0E49-F040-4231-83F6-34FFCA99F517" },
    { "nf", "382CBAE0-3040-47CD-9306-B575955EDF58" },
    { "nn", "C50C00B1-EFE9-4718-8B87-7DD6E6C9FB5D" },
};
std::string getpath(const std::string& tag)
{
    return stringformat("/Volumes/SnowLeopard/Applications/Van Dale Woordenboeken/g%s3.vdw", tag.c_str());
}
void calcmd5key(const std::string&key, uint8_t*md5key)
{
    std::Wstring wkey= ToWString(key);

    Md5 m;
    m.add((const uint8_t*)&wkey[0], wkey.size()*2);
    m.final(md5key);

    for (int i=0 ; i<15 ; i++)
    {
        Md5 mi;
        mi.add(md5key+i*16, 16);
        mi.final(md5key+i*16+16);
    }
}
template<typename T>
struct circular_iterator {

    typedef typename T::value_type value_type;
    typedef value_type& reference;
    typedef value_type* pointer;
    typedef int difference_type;
    typedef std::random_access_iterator_tag iterator_category;

    typename T::const_iterator first;
    typename T::const_iterator last;
    typename T::const_iterator p;

    circular_iterator(const T& v)
        : first(v.begin()), last(v.end()), p(first)
    {
    }
    value_type operator*()
    {
        return *p;
    }
    // prefix inc
    circular_iterator& operator++()
    {
        ++p;
        if (p==last)
            p= first;
        return *this;
    }
    // postfix inc
    circular_iterator operator++(int)
    {
        circular_iterator  copy= *this;
        operator++();
        return copy;
    }
    void setpos(size_t n)
    {
        p= first + n%(last-first);
    }

//  circular_iterator& operator+=(int n) { p= first+(p-first+n)%(last-first); return *this; }
//  circular_iterator operator+(int n) { return circular_iterator(first, last, ); }
//  circular_iterator& operator-=(int n) { _blocknr-=n; return *this; }
//  circular_iterator operator-(int n) { return circular_iterator(_bi, _r, _blocknr-n); }
//  int operator-(const circular_iterator&rhs) const { return blocknr()-rhs.blocknr(); }

//  bool operator==(const circular_iterator&rhs) const { return blocknr()==rhs.blocknr(); }
//  bool operator!=(const circular_iterator&rhs) const { return blocknr()!=rhs.blocknr(); }
//  bool operator<=(const circular_iterator&rhs) const { return blocknr()<=rhs.blocknr(); }
//  bool operator< (const circular_iterator&rhs) const { return blocknr()< rhs.blocknr(); }
//  bool operator>=(const circular_iterator&rhs) const { return blocknr()>=rhs.blocknr(); }
//  bool operator> (const circular_iterator&rhs) const { return blocknr()> rhs.blocknr(); }

};
template<typename V>
circular_iterator<V> makecircular(const V&v)
{
    return circular_iterator<V>(v);
}

class xorreader : public ReadWriter {
    circular_iterator<std::vector<uint8_t> > _x;
    const uint8_t *_first;
    const uint8_t *_last;
    const uint8_t *_cur;
public:
    xorreader(const std::vector<uint8_t>& key, const uint8_t *first, const uint8_t*last)
        : _x(key), _first(first), _last(last), _cur(_first)
    {
    }
    virtual size_t read(uint8_t *p, size_t n)
    {
        size_t want= std::min(n, size_t(_last-_cur));
        for (size_t i= 0 ; i<want ; i++)
            *p++ = *_cur++ ^ *_x++;
        return want;
    }
    virtual void write(const uint8_t *p, size_t n)
    {
        throw "xorreader is readonly";
    }
    virtual void setpos(uint64_t off)
    {
        if (off > size())
            throw "xor.setpos: pos too large";
        _cur= _first+off;
        _x.setpos(off);
    }
    virtual void truncate(uint64_t off)
    {
        throw "xorreader is readonly";
    }
    virtual uint64_t size()
    {
        return _last-_first;
    }
    virtual uint64_t getpos() const
    {
        return _cur-_first;
    }
    virtual bool eof()
    {
        return _cur==_last;
    }
};
void decompress(const uint8_t *p)
{
    uint32_t size= get32le(p);

    ZlibDecompress z;
    z.add(p+4, size);
    ByteVector data;
    while (!z.eof())
    {
        data.resize(data.size()+0x10000);
        size_t n= z.get(&data[data.size()-0x10000], 0x10000);
        data.resize(data.size()-0x10000+n);
    }
    printf("=========\n");
    fwrite(&data[0], data.size(),1, stdout);
    printf("\n=========\n");
}
void dumpblobsection(const std::vector<uint8_t>& M, const uint8_t *filebase, uint32_t len, uint32_t ofs)
{
    const uint8_t *P= filebase+ofs;
    xorreader I(M, P+16, P+16+0xd0);
    I.setpos(0x38);
    uint32_t pblob= I.read32le();
    /*uint32_t sblob=*/ I.read32le();
    uint32_t ptable= I.read32le();
    uint32_t stable= I.read32le();

    xorreader T(M, P+ptable, P+ptable+stable);

    std::set<uint32_t> ptrs;
    while (!T.eof())
    {
        ptrs.insert(T.read32le());
        T.read32le();
        T.read32le();
        T.read16le();
    }
    for (auto i=ptrs.begin() ; i!=ptrs.end() ; ++i)
        decompress(P+pblob+*i);
}
void dumpindex(const std::vector<uint8_t>& M, const uint8_t *filebase, const uint8_t *sectionbase, uint32_t len, uint32_t ofs)
{
    printf("index[%08x %08x]\n", ofs, len);
    xorreader I(M, sectionbase+ofs, sectionbase+ofs+len);
    uint32_t count= I.read32le();
    for (unsigned i=0 ; i<count ; i++)
    {
        uint32_t type= I.read32le();
        if (type==0x10001) {
            printf("%08x: %08x %08x\n", type, I.read32le(), I.read32le());
        }
        else if ((type>>16)==5) {
            printf("%08x: %08x %08x\n", type, I.read32le(), I.read32le());
        }
        else if (type==0x20001) {
            uint32_t ptr= I.read32le();
            uint32_t siz= I.read32le();
            uint32_t unk= I.read32le();
            printf("%08x: %08x %08x %08x\n", type, unk, siz, ptr);
            dumpblobsection(M, filebase,siz, ptr);
        }
        else if ((type>>16)==3) {
            printf("%08x: %08x %08x %08x %08x\n", type, I.read32le(), I.read32le(), I.read32le(), I.read32le());
        }
        else {
            printf("unknown [c=%x, t=%08x, i=%d]\n", count, type, i);
            break;
        }
    }
}

void process_vdw(const std::string& key, const uint8_t *first, const uint8_t *last)
{
    Md5 filehash;
    filehash.add(first+16, last-first-16);
    std::array<uint8_t,Md5::DigestSize> digest;
    filehash.final(&digest.front());

    if (!std::equal(digest.begin(), digest.end(), first)) {
        printf("filehash mismatch\n");
        throw "error";
    }
    const uint8_t *p= first+16;
    printf("+10: unknown:  %s\n", hexdump(p, 26).c_str());

    p+=26;
    
    std::array<uint8_t,20> rootdata;

    auto x= makecircular(std::string("vdw"));
    std::transform(p, p+20, rootdata.begin(), [&x](uint8_t v) { return v^*++x; });

    p+=20;

    uint32_t unk0= get32le(&rootdata[0]);
    uint32_t troot= get32le(&rootdata[4]);
    uint32_t proot= get32le(&rootdata[8]);
    uint32_t sroot= get32le(&rootdata[12]);
    uint32_t cplen= get32le(&rootdata[16]);

    printf("root: %d, %x, @%x:%x, copyrightlen=%x\n", unk0, troot, proot, sroot, cplen);

    std::string copyright= ToString(std::Wstring((WCHAR*)p, ((WCHAR*)p)+cplen));

    p+= cplen*2;

    std::vector<uint8_t> M(256);
    
    calcmd5key(key, &M[0]);

    xorreader cpr(M, p, p+cplen*2);

    std::Wstring cp2;
    cpr.readutf16le(cp2, cplen);

    if (ToString(cp2)!=copyright) {
        printf("copyright strings don't match\n");
        throw "error";
    }
    printf("%s\n", copyright.c_str());
    
    xorreader root(M, first+proot+16, first+proot+16+0xc0);

    root.setpos(16);
    printf("%08x %08x %08x  section\n", root.read32le(), root.read32le(), root.read32le());
    printf("%08x %08x %08x  str1\n", root.read32le(), root.read32le(), root.read32le());
    printf("%08x %08x %08x  str2\n", root.read32le(), root.read32le(), root.read32le());
    printf("%08x %08x %08x  str3\n", root.read32le(), root.read32le(), root.read32le());
    printf("%08x %08x %08x  unk\n", root.read32le(), root.read32le(), root.read32le());

    dumpindex(M, first, first+proot, root.read32le(), root.read32le());
    dumpindex(M, first, first+proot, root.read32le(), root.read32le());
    printf("%08x %08x       dw+strings\n", root.read32le(), root.read32le());
    dumpindex(M, first, first+proot, root.read32le(), root.read32le());
    dumpindex(M, first, first+proot, root.read32le(), root.read32le());
    for (int i=5 ; i<12 ; i++)
        printf("%08x %08x       pix%d\n", root.read32le(), root.read32le(), i);
}

int main(int argc, char**argv)
{
    if (argc!=2) {
        printf("Usage: vdwreader <lang>\n");
        return 1;
    }
    auto ent= keymap.find(argv[1]);
    if (ent==keymap.end()) {
        printf("unknown language\n");
        return 1;
    }

    try {
    MmapReader r(getpath(argv[1]), MmapReader::readonly);

    if (r.size()<16) {
        printf("vdw too short\n");
        return 1;
    }
    process_vdw(ent->second, r.begin(), r.end());

    }
    catch(const char*msg)
    {
        printf("E: %s\n", msg);
    }
    printf("done\n");
    return 0;
}

