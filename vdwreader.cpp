#include <stdio.h>
#include "crypto/hash.h"
#include "util/HiresTimer.h"
#include "util/ReadWriter.h"
#include "util/rw/MmapReader.h"
#include "util/rw/CompressedReader.h"
#include "compress/zlib.h"
#include <array>
#include <set>
#include <map>
#include "args.h"
#include "stringutils.h"

class areausage {
    struct areainfo {
        uint32_t offset;
        uint32_t length;
        std::string desc;

        areainfo(uint32_t offset, uint32_t length, const std::string& desc)
            : offset(offset), length(length), desc(desc)
        {
        }

    };
    typedef std::map<uint32_t,areainfo> areamap;

    uint32_t _size;
    areamap _map;
public:
    areausage (uint32_t size)
        : _size(size)
    {
    }
    void add(uint32_t offset, uint32_t length, const std::string& desc)
    {
        _map.insert(areamap::value_type(offset, areainfo(offset, length, desc)));
    }

    void dump()
    {
        uint32_t ofs= 0;
        for (auto const&i : _map)
        {
            if (ofs<i.first) {
                printf("... gap: %08x-%08x\n", ofs, i.first);
            }
            else if (ofs>i.first) {
                printf("... overlap: %08x-%08x\n", i.first, ofs);
            }
            printf("%08x-%08x: %s\n", i.second.offset, i.second.offset+i.second.length, i.second.desc.c_str());
            ofs= i.second.offset+i.second.length;
        }
        if (ofs<_size) {
            printf("... gap: %08x-%08x\n", ofs, _size);
        }
        else if (ofs>_size) {
            printf("... too large: %08x-%08x\n", _size, ofs);
        }
    }
};
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

class Section {
    const std::vector<uint8_t>& M;
    uint32_t _type;
    const uint8_t* _first;
    const uint8_t* _last;
    std::string _name;
    std::string _desc;

    areausage _usage;
protected:
    void usage(uint32_t offset, uint32_t length, const std::string& desc)
    {
        _usage.add(offset, length, desc);
    }
    void setname(const std::string& name) { _name= name; }
    void setdesc(const std::string& desc) { _desc= desc; }

    ReadWriter_ptr makexorreader(uint32_t ofs, uint32_t len)
    {
        return ReadWriter_ptr(new xorreader(M, _first+ofs, _first+ofs+len));
    }
    ReadWriter_ptr makehdrreader()
    {
        return makexorreader(0x10, headersize());
    }

    const uint8_t* getptr(uint32_t ofs)
    {
        return _first+ofs;
    }
    uint32_t size()
    {
        return _last-_first;
    }

    std::string readstr(ReadWriter_ptr r)
    {
        uint32_t p= r->read32le();
        uint32_t nbytes= r->read32le();
        /*uint32_t nchars=*/ r->read32le();  // # utf8 symbols

        return readstr(p, nbytes);
    }
    std::string readstr(uint32_t p, uint32_t l)
    {
        usage(p,l, "string");

        ReadWriter_ptr srd= makexorreader(p, l);

        return srd->readstr();
    }
    void verifyheader()
    {
        ReadWriter_ptr hdr= makehdrreader();

        ByteVector hdrdata(headersize());
        hdr->read(&hdrdata[0], headersize());

        Md5 hash;
        std::array<uint8_t,Md5::DigestSize> digest;
        hash.add(&hdrdata[16], hdrdata.size()-16);
        hash.final(&digest.front());

        if (!std::equal(digest.begin(), digest.end(), &hdrdata[0])) {
            printf("header hash mismatch [%08x]  %s\n", type(), vhexdump(hdrdata).c_str());
            throw "header md5 error";
        }
        printf("section header %08x ok\n", type());
    }
    virtual void verifysection() { }
    virtual uint32_t headersize() const { return 0; }


public:
    uint32_t type() const { return _type; }

    Section(const std::vector<uint8_t>& M, uint32_t type, const uint8_t* first, const uint8_t* last)
        : M(M), _type(type), _first(first), _last(last), _usage(last-first)
    {
        usage(0, 16, "plain, section md5");
    }
    virtual ~Section() { }
    const std::string& name() const { return _name; }
    const std::string& desc() const { return _desc; }

    void verify()
    {
        Md5 hash;
        std::array<uint8_t,Md5::DigestSize> digest;
        hash.add(getptr(16), size()-16);
        hash.final(&digest.front());

        if (!std::equal(digest.begin(), digest.end(), getptr(0))) {
            printf("section hash mismatch\n");
            throw "section md5 error";
        }
        printf("section %08x ok\n", type());
        if (headersize()) {
            verifyheader();
        }

        verifysection();
    }
    void dumpusage()
    {
        printf("usage of section %s\n", _name.c_str());
        _usage.dump();
    }

    void savedata(uint32_t ofs, uint32_t len, const std::string& path, const std::string& dataname)
    {
        ReadWriter_ptr rd= makexorreader(ofs, len);
        ReadWriter_ptr wr(new FileReader(stringformat("%s/%s.%s", path.c_str(), name().c_str(), dataname.c_str()), FileReader::createnew));
        rd->copyto(wr);
    }
    void saveplain(uint32_t ofs, uint32_t len, const std::string& path, const std::string& dataname)
    {
        ReadWriter_ptr wr(new FileReader(stringformat("%s/%s.%s", path.c_str(), name().c_str(), dataname.c_str()), FileReader::createnew));

        while (len) {
            if (len<4) {
                printf("WARN: blob error\n");
                break;
            }
            uint32_t chunk= get32le(getptr(ofs)); ofs+=4; len-=4;

            if (len<chunk) {
                printf("WARN: blob error\n");
                break;
            }

            ReadWriter_ptr M(new MemoryReader(getptr(ofs), chunk));
            ReadWriter_ptr D(new CompressedReader(M));
            D->copyto(wr);
            ofs+=chunk;
            len-=chunk;
        }
    }
    virtual void saveall(const std::string& path)
    {
    }
};
typedef boost::shared_ptr<Section> Section_ptr;

class RootSection : public Section {

    struct indexptr {
        uint32_t type;
        uint32_t ofs;
        uint32_t size;

        indexptr( uint32_t type, uint32_t ofs, uint32_t size)
            : type(type), ofs(ofs), size(size)
        {
        }
    };
    std::vector<indexptr> _ixlist;

    std::string _version;

    void readindex(ReadWriter_ptr r)
    {
        uint32_t ofs= r->read32le();
        uint32_t len= r->read32le();

        usage(ofs, len, "rootindex");

        printf("index[%08x %08x]\n", ofs, len);

        ReadWriter_ptr I= makexorreader(ofs, len);
        uint32_t count= I->read32le();
        for (unsigned i=0 ; i<count ; i++)
        {
            uint32_t type= I->read32le();
            if (type==0x10001 || (type>>16)==5) {
                uint32_t gofs= I->read32le();
                uint32_t glen= I->read32le();
                printf("%08x: %08x %08x\n", type, gofs, glen);
                _ixlist.push_back(indexptr(type, gofs, glen));
            }
            else if (type==0x20001) {
                uint32_t gofs= I->read32le();
                uint32_t glen= I->read32le();
                uint32_t unk= I->read32le();
                printf("%08x: %08x %08x [ %08x ]\n", type, gofs, glen, unk);
                _ixlist.push_back(indexptr(type, gofs, glen));
            }
            else if ((type>>16)==3) {
                uint32_t gofs= I->read32le();
                uint32_t glen= I->read32le();
                printf("%08x: %08x %08x [ %08x %08x ]\n", type, gofs, glen, I->read32le(), I->read32le());
                _ixlist.push_back(indexptr(type, gofs, glen));
            }
            else {
                printf("unknown [c=%x, t=%08x, i=%d]\n", count, type, i);
                break;
            }
        }
    }
    void readdwstrings(uint32_t ofs, uint32_t len)
    {
        usage(ofs, len, "dw+strings");
    }


public:
    virtual uint32_t headersize() const { return 0xac; }

    RootSection(const std::vector<uint8_t>& M, uint32_t type, const uint8_t* first, const uint8_t* last)
        : Section(M, type, first, last)
    {
        usage(0x10, headersize(), "root section header");
        ReadWriter_ptr hdr= makehdrreader();

        hdr->setpos(16);
        uint32_t unknown= hdr->read32le();
        uint32_t size2= hdr->read32le();
        uint32_t type2= hdr->read32le();
        if (unknown!=1)
            printf("WARN: !=1: %08x\n", unknown);
        if (size2!=last-first)
            printf("WARN: sectionsize mismatch: %08x (iso %08x)\n", size2, uint32_t(last-first));
        if (type2!=type)
            printf("WARN: sectiontype mismarch: %08x (iso %08x)\n", type2, type);

        setname(readstr(hdr));
        setdesc(readstr(hdr));
        _version= readstr(hdr);  printf("vers: %s\n", _version.c_str());
        printf("unknown: %08x %08x %08x\n", hdr->read32le(), hdr->read32le(), hdr->read32le());

        readindex(hdr);
        readindex(hdr);
        uint32_t dwstrofs= hdr->read32le();
        uint32_t dwstrlen= hdr->read32le();

        readdwstrings(dwstrofs, dwstrlen);

        readindex(hdr);
        readindex(hdr);
        for (int i=5 ; i<12 ; i++) {
            uint32_t xofs= hdr->read32le();
            uint32_t xlen= hdr->read32le();
            printf("%08x %08x     unknown  pix%d\n", xofs, xlen, i);
            if (xlen)
                usage(xofs, xlen, stringformat("pix%d", i));
        }
    }
    bool getsection(unsigned n, uint32_t *ofs, uint32_t *len, uint32_t *type)
    {
        if (n>=_ixlist.size())
            return false;

        auto i= _ixlist.begin()+n;
        *ofs= i->ofs;
        *len= i->size;
        *type= i->type;
        return true;
    }
};
typedef boost::shared_ptr<RootSection> RootSection_ptr;

class BlobSection : public Section {
    uint32_t _nitems;
    uint32_t _pblob;
    uint32_t _sblob;
           
    uint32_t _ptab;
    uint32_t _stab;

    struct strinfo {
        uint32_t ofs;
        uint32_t len;

        strinfo(uint32_t ofs, uint32_t len)
            : ofs(ofs), len(len)
        {
        }
    };
    std::vector<strinfo> _strs;
#if 0
    void decompress(uint32_t blobofs)
    {
        auto uint8_t *p= getptr(_pblob)+blobofs;

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
        fwrite(&data[0], data.size(),1, stdout);
    }
    void dumpblobsection(uint32_t ofs, uint32_t len)
    {
        ReadWriter_ptr T= makexorreader(ofs, len);

        std::set<uint32_t> ptrs;
        while (!T->eof())
        {
            ptrs.insert(T->read32le());
            T->read32le();
            T->read32le();
            T->read16le();
        }
        for (auto i=ptrs.begin() ; i!=ptrs.end() ; ++i)
            decompress(*i);
    }
#endif
public:
    virtual uint32_t headersize() const { return 0xe0; }

    BlobSection(const std::vector<uint8_t>& M, uint32_t type, const uint8_t* first, const uint8_t* last)
        : Section(M, type, first, last)
    {
        usage(0x10, headersize(), "blob section header");
        ReadWriter_ptr hdr= makehdrreader();

        hdr->setpos(16);
        uint32_t unknown= hdr->read32le();
        uint32_t size2= hdr->read32le();
        uint32_t type2= hdr->read32le();
        uint32_t unknown2= hdr->read32le();
        if (unknown!=1)
            printf("WARN: +16  !=1: %08x\n", unknown);
        if (size2!=last-first)
            printf("WARN: sectionsize mismatch: %08x (iso %08x)\n", size2, uint32_t(last-first));
        if (type2!=type)
            printf("WARN: sectiontype mismarch: %08x (iso %08x)\n", type2, type);
        if (unknown2!=1 && unknown2!=2)
            printf("WARN: +28  !=1: %08x\n", unknown2);


        _nitems= hdr->read32le();

        uint32_t n_unk1=hdr->read32le(); 
        uint32_t n_unk2=hdr->read32le(); 
        uint32_t n_unk3=hdr->read32le(); 
        uint32_t n_unk4=hdr->read32le(); 
        uint32_t n_unk5=hdr->read32le(); 
        printf("unknown: %6d %6d %6d %6d %08x\n", n_unk1, n_unk2, n_unk3, n_unk4, n_unk5);


        _pblob= hdr->read32le();
        _sblob= hdr->read32le();
        usage(_pblob, _sblob, "compressed blob");

        _ptab= hdr->read32le();
        _stab= hdr->read32le();
        usage(_ptab, _stab, "blob index");

        //dumpblobsection(_ptab, _stab);

        setname(readstr(hdr));
        setdesc(readstr(hdr));
        for (int i=0 ; i<8 ; i++)
        {
            uint32_t sofs= hdr->read32le();
            uint32_t snbytes= hdr->read32le();
            uint32_t snchars= hdr->read32le();
            uint32_t snul= hdr->read32le();
            if (snbytes || snchars)
                printf("%08x:%08x:%08x  longstring\n", sofs, snbytes, snchars);
            if (snul)
                printf("WARN: !=0: %08x\n", snul);
            if (snbytes) {
                usage(sofs, snbytes, "longstring");
                _strs.push_back(strinfo(sofs, snbytes));
            }
        }
    }
    virtual void saveall(const std::string& path)
    {
        savedata(_ptab, _stab, path, "table");
        saveplain(_pblob, _sblob, path, "blob");
        for (unsigned i=0 ; i<_strs.size() ; i++)
            savedata(_strs[i].ofs, _strs[i].len, path, stringformat("string%d", i));
    }
    std::string getitem(uint32_t ix)
    {
        if (ix>=_nitems)
            throw "item index too large";
        ReadWriter_ptr I= makexorreader(_ptab, _stab);
        I->setpos(14*ix);

        uint32_t blobofs= I->read32le();
        uint32_t streamofs= I->read32le();
        uint32_t itemsize= I->read32le();
        uint32_t unknul= I->read16le();
        if (unknul!=0)
            printf("WARN: item unk!=0: %04x\n", unknul);

        //printf("B+%08x, S+%08x/%08x\n", blobofs, streamofs, itemsize);

        uint32_t chunksize= get32le(getptr(_pblob)+blobofs);

        ReadWriter_ptr B= ReadWriter_ptr(new MemoryReader(getptr(_pblob)+blobofs+4, chunksize));
        ReadWriter_ptr Z= ReadWriter_ptr(new CompressedReader(B));

        return Z->readstr(streamofs, itemsize);
    }

    void dumpinfo()
    {
        printf("n=%d, blob:%x/%d, tab:%x/%d\n", _nitems, _pblob, _sblob, _ptab, _stab);
        for (unsigned i=0 ; i<_nitems ; i+=_nitems/16)
            printf("%8d : %s\n", i, getitem(i).c_str());
    }
};
typedef boost::shared_ptr<BlobSection> BlobSection_ptr;

class IndexSection : public Section {
    uint32_t _count1;
    uint32_t _count2;
    uint32_t _ptable1;
    uint32_t _ptable2;
    uint32_t _ptable3;
    uint32_t _pwords;
    uint32_t _ptable4;
    uint32_t _ptable5;
    uint32_t _lwords;
    uint32_t _bm_count;
    uint32_t _bm_ofs;   // todo: bitmap decoder
    uint32_t _bm_len;
public:
    virtual uint32_t headersize() const { return (type()&0xfffffff0)==0x0030100 ? 0xb4 : 0xc0; }

    IndexSection(const std::vector<uint8_t>& M, uint32_t type, const uint8_t* first, const uint8_t* last)
        : Section(M, type, first, last),
            _count1(0), _count2(0), _ptable1(0), _ptable2(0), _ptable3(0),
            _pwords(0), _ptable4(0), _ptable5(0), _lwords(0)
    {
        usage(0x10, headersize(), "index section header");
        ReadWriter_ptr hdr= makehdrreader();
        hdr->setpos(16);

        uint32_t unknown= hdr->read32le();
        uint32_t size2= hdr->read32le();
        uint32_t type2= hdr->read32le();
        uint32_t flags= hdr->read32le();
        if (unknown!=1)
            printf("WARN: +16  !=1: %08x\n", unknown);
        if (size2!=last-first)
            printf("WARN: sectionsize mismatch: %08x (iso %08x)\n", size2, uint32_t(last-first));
        if (type2!=type)
            printf("WARN: sectiontype mismarch: %08x (iso %08x)\n", type2, type);
        printf("flags: %08x\n", flags);

        uint32_t pstr1= hdr->read32le();
        uint32_t pstr2= hdr->read32le();

        uint32_t lstr1bytes= hdr->read32le();
        /*uint32_t lstr1chars=*/ hdr->read32le();
        uint32_t lstr2bytes= hdr->read32le();
        /*uint32_t lstr2chars=*/ hdr->read32le();

        setname(readstr(pstr1, lstr1bytes));
        setdesc(readstr(pstr2, lstr2bytes));

        printf("unknown: %08x %08x %08x %08x\n", hdr->read32le(), hdr->read32le(), hdr->read32le(), hdr->read32le());

        _count1= hdr->read32le();
        uint32_t maxval= hdr->read32le();
        printf("max t1 value: %08x\n", maxval);

        _count2= type==0x00030206 ? hdr->read32le() : 0;
        uint32_t unk2= hdr->read32le();
        uint32_t unk3= hdr->read32le();
        _ptable1= hdr->read32le();
        if (unk2!=_ptable1 || unk3!=_ptable1)
            printf("WARN: unkptrs != tab1: %08x %08x\n", unk2, unk3);
        _ptable2= hdr->read32le();
        _ptable3= hdr->read32le();
        uint32_t unk4= hdr->read32le();
        if (unk4!=_ptable3)
            printf("WARN: unkptr != tab3: %08x\n", unk4);
        _pwords= hdr->read32le();
        _ptable4= type==0x00030206 ? hdr->read32le() : 0;
        _ptable5= type==0x00030206 ? hdr->read32le() : 0;
        uint32_t unk5= hdr->read32le();
        if (unk5!=0)
            printf("WARN: unkval!=0 : %08x\n", unk5);
        _lwords= hdr->read32le();

        usage(_ptable1, _count1*4, "table1");
        usage(_ptable2, _count1*4, "table2");
        usage(_ptable3, _count1*4, "table3");
        if (_ptable4) {
            usage(_ptable4, _count2*6, "table4");
            usage(_ptable5, _count2*4, "table5");
        }
        usage(_pwords, _lwords, "words");

        // bitmap ??
        for (int i=0 ; i<8 ; i++)
        {
            uint32_t bo= hdr->read32le();
            uint32_t bl= hdr->read32le();
            if (bl) {
                std::string desc= i==0?"prebitmap":i==1?"bitmapptr":stringformat("unknownbitmap-%d", i);
                printf("%08x %08x  %s\n", bo, bl, desc.c_str());
                usage(bo, bl, desc);
            }
            if (i==1)
            {
                ReadWriter_ptr bmr= makexorreader(bo, bl);
                _bm_count= bmr->read32le();
                _bm_ofs= bmr->read32le();
                _bm_len= bmr->read32le();
                usage(_bm_ofs, _bm_len, "bitmap");
            }
        }
//      if (_ptable4)
//          dump45();
//      else
//          dump3();
    }
    virtual ~IndexSection() { }
    virtual void saveall(const std::string& path)
    {
        savedata(_ptable1, _count1*4, path, "table1");
        savedata(_ptable2, _count1*4, path, "table2");
        savedata(_ptable3, _count1*4, path, "table3");
        if (_ptable4) {
            savedata(_ptable4, _count2*6, path, "table4");
            savedata(_ptable5, _count2*4, path, "table5");
        }
        savedata(_pwords, _lwords, path, "words");
        savedata(_bm_ofs, _bm_len, path, "bitmap");
    }
    std::string getword(uint32_t ix)
    {
        if (ix>=_count1)
            throw "index out of range";
        ReadWriter_ptr rt3= makexorreader(_ptable3, 4*_count1);
        rt3->setpos(4*ix);
        uint32_t wofs= rt3->read32le();
        uint32_t eofs= (ix==_count1-1) ? _lwords : rt3->read32le();

        ReadWriter_ptr wrd= makexorreader(_pwords, _lwords);

        return wrd->readstr(wofs+2, eofs-wofs);
    }
    void dump45()
    {
        printf("3:%08x/%d, 4:%08x/%d, 5:%08x/%d, w:%08x/%d\n",
                _ptable3, _count1,
                _ptable4, _count2,
                _ptable5, _count2,
                _pwords, _lwords);
        ReadWriter_ptr rt4= makexorreader(_ptable4, 6*_count2);
        ReadWriter_ptr rt5= makexorreader(_ptable5, 4*_count2);
        ReadWriter_ptr rtw= makexorreader(_pwords, _lwords);
        ReadWriter_ptr rt3= makexorreader(_ptable3, 4*_count1);

        std::vector<uint32_t> t4o;
        std::vector<uint16_t> t4l;
        std::vector<uint32_t> t5;
        std::vector<uint32_t> t3o;
        std::vector<std::string> tw;

        for (unsigned i=0 ; i<_count1 ; i++) {
            t3o.push_back(rt3->read32le());
        }
        while (!rtw->eof()) {
            uint16_t slen= rtw->read16le();
            std::string str; str.resize(slen);
            rtw->read((uint8_t*)&str[0], slen);
            tw.push_back(str);
        }
        for (unsigned i=0 ; i<_count2 ; i++) {
            t4o.push_back(rt4->read32le());
            t4l.push_back(rt4->read16le());
        }
        for (unsigned i=0 ; i<_count2 ; i++) {
            t5.push_back(rt5->read32le());
        }
        printf("3:%llx/%d 4:%llx/%d 5:%llx/%d w:%llx/%d\n",
                rt3->getpos(), rt3->eof(),
                rt4->getpos(), rt4->eof(),
                rt5->getpos(), rt5->eof(),
                rtw->getpos(), rtw->eof());

        for (unsigned i=0 ; i<_count2 ; i++)
        {
            std::string& s= tw[t5[i]];
            printf("%08x: 4[%08x/%04x]  5[%08x->%08x] %*s%s\n",
                    i, t4o[i], t4l[i], t5[i], t3o[t5[i]], 35-t4l[i], "", s.c_str());
        }
    }
    void dump3()
    {
        ReadWriter_ptr rtw= makexorreader(_pwords, _lwords);
        ReadWriter_ptr rt3= makexorreader(_ptable3, 4*_count1);

        std::vector<uint32_t> t3o;
        std::vector<std::string> tw;

        for (unsigned i=0 ; i<_count1 ; i++) {
            t3o.push_back(rt3->read32le());
        }
        while (!rtw->eof()) {
            uint16_t slen= rtw->read16le();
            std::string str; str.resize(slen);
            rtw->read((uint8_t*)&str[0], slen);
            tw.push_back(str);
        }
        printf("3:%llx/%d  w:%llx/%d\n",
                rt3->getpos(), rt3->eof(),
                rtw->getpos(), rtw->eof());

        for (unsigned i=0 ; i<_count1 ; i++)
        {
            printf("%08x: 3[%08x]'%s'\n",
                    i, t3o[i], tw[i].c_str());
        }
    }

    struct lessthen {
        bool operator()(const std::string &l, const std::string &r)
        {
            int cmp= stringicompare(l,r);
            //printf("%34s    %c    %s\n", l.c_str(), cmp<0?'<':cmp>0?'>':'=', r.c_str());
            // todo: utf8 stringcompare ( which correctly handles multibyte characters
            return cmp<0;
        }
    };
    void rhexdump(ReadWriter_ptr r, uint64_t ofs, uint64_t len)
    {
        r->setpos(ofs);
        while (len) {
            ByteVector data(32);
            size_t n= r->read(&data[0], data.size());
            if (n==0)
                break;

            printf("%08llx: %s\n", ofs, hexdump(&data[0], n).c_str());

            len -= n;
            ofs += n;
        }
    }
    // returns set of headword indexes matching str
    std::set<uint32_t> stringsearch(const std::string& str)
    {
        lessthen lt;
        ReadWriter_ptr rtw= makexorreader(_pwords, _lwords);
        ReadWriter_ptr rt3= makexorreader(_ptable3, 4*_count1);

        //printf("words: %08x/%08x\n", _pwords, _lwords);
        //rhexdump(rtw, 0, 256);
        //printf("t3: %08x/%08x\n", _ptable3, 4*_count1);
        //rhexdump(rt3, 0, 256);

        auto first= stringiterator(rt3, rtw, 0);
        auto last= stringiterator(rt3, rtw, _count1);
        //auto r= std::equal_range(first, last, str, lt);
        //  eq: *(i-1)<str && str<=*i && *(j-1)<=str && str<*j

        auto lb= std::lower_bound(first, last, str, lt);
        //  lb: *(i-1)<str && str<=*i
        auto ub= std::upper_bound(first, last, str, lt);
        //  ub: *(i-1)<=str && str<*i

//      printf("lb:%08x(%s)  .. ub:%08x(%s)\n", 
//              lb.index(), lb!=last?(*lb).c_str():"<END>", 
//              ub.index(), ub!=last?(*ub).c_str():"<END>");

        ReadWriter_ptr rt1= makexorreader(_ptable1, 4*_count1);
        std::set<uint32_t> items;
        for (auto i= lb ; i!=ub ; i++) {
            items.insert(rt1->read32le(4*i.index()));
        }
        return items;
    }

    // returns set of headword indexes matching str
    std::set<uint32_t> substrsearch(const std::string& str)
    {
        lessthen lt;
        ReadWriter_ptr rtw= makexorreader(_pwords, _lwords);
        ReadWriter_ptr rt4= makexorreader(_ptable4, 6*_count2);

        auto first= substriterator(rt4, rtw, 0);
        auto last= substriterator(rt4, rtw, _count2);

        auto lb= std::lower_bound(first, last, str, lt);
        //  lb: *(i-1)<str && str<=*i
        auto ub= std::upper_bound(first, last, str, lt);
        //  ub: *(i-1)<=str && str<*i

        ReadWriter_ptr rt5= makexorreader(_ptable5, 4*_count2);
        ReadWriter_ptr rt1= makexorreader(_ptable1, 4*_count1);
        std::set<uint32_t> items;
        for (auto i= lb ; i!=ub ; i++) {
            uint32_t t5val= rt5->read32le(4*i.index());
            items.insert(rt1->read32le(4*t5val));
        }
        return items;
    }

    class iterator {
    protected:
        ReadWriter_ptr _tab;
        ReadWriter_ptr _words;
        uint32_t _ix;
    public:
        typedef std::string& reference;
        typedef std::string* pointer;
        typedef int difference_type;
        typedef std::string value_type;
        typedef std::random_access_iterator_tag iterator_category;

        iterator(const iterator& i)
            : _tab(i._tab), _words(i._words), _ix(i._ix)
        {
        }
        iterator(ReadWriter_ptr tab, ReadWriter_ptr words, uint32_t ix)
            : _tab(tab), _words(words), _ix(ix)
        {
        }
        iterator()
            : _ix(0)
        {
        }

        // prefix opperator
        iterator& operator++()
        {
            _ix++;
            return *this;
        }
        iterator& operator--()
        {
            _ix--;
            return *this;
        }

        // postfix opperator
        iterator operator--(int)
        {
            iterator copy= *this;
            operator--();
            return copy;
        }

        iterator operator++(int)
        {
            iterator copy= *this;
            operator++();
            return copy;
        }
        iterator& operator+=(int n) { _ix+=n; return *this; }
        iterator operator+(int n) { return iterator(_tab, _words, _ix+n); }
        iterator& operator-=(int n) { _ix-=n; return *this; }
        iterator operator-(int n) { return iterator(_tab, _words, _ix-n); }
        int operator-(const iterator&rhs) const { return _ix-rhs._ix; }

        bool operator==(const iterator&rhs) const { return _ix==rhs._ix; }
        bool operator!=(const iterator&rhs) const { return _ix!=rhs._ix; }
        bool operator<=(const iterator&rhs) const { return _ix<=rhs._ix; }
        bool operator< (const iterator&rhs) const { return _ix< rhs._ix; }
        bool operator>=(const iterator&rhs) const { return _ix>=rhs._ix; }
        bool operator> (const iterator&rhs) const { return _ix> rhs._ix; }

        uint32_t index() const { return _ix; }
    };


    class stringiterator : public iterator {
    public:
        stringiterator(ReadWriter_ptr tab, ReadWriter_ptr words, uint32_t ix)
            : iterator(tab, words, ix)
        {
        }
        stringiterator() { }
        std::string operator*()
        {
            _tab->setpos(4*_ix);
            uint32_t wofs= _tab->read32le();
            _words->setpos(wofs);
            uint16_t wlen= _words->read16le();

            std::string word;
            _words->readstr(word, wlen);
            //printf("striter[%08x->%08x]=%04x:%s\n", _ix, wofs, wlen, word.c_str());
            return word;
        }
        stringiterator& operator++()
        {
            return (stringiterator&)iterator::operator++();
        }
        stringiterator operator++(int)
        {
            stringiterator i= *this;
            iterator::operator++();
            return i;
        }

    };

    class substriterator : public iterator {
    public:
        substriterator(ReadWriter_ptr tab, ReadWriter_ptr words, uint32_t ix)
            : iterator(tab, words, ix)
        {
        }
        substriterator() { }
        std::string operator*()
        {
            _tab->setpos(6*_ix);
            uint32_t wofs= _tab->read32le();
            uint16_t strofs= _tab->read16le();
            _words->setpos(wofs);
            uint16_t wlen= _words->read16le();

            std::string word= _words->readstr(wofs+2+strofs, wlen-strofs);
            //printf("subiter[%08x->%08x:%04x]=%04x:%s\n", _ix, wofs, strofs, wlen, word.c_str());
            return word;
        }
        // note: clang++ has become more strict: have to duplicate operator++ here
        substriterator& operator++()
        {
            return (substriterator&)iterator::operator++();
        }
        substriterator operator++(int)
        {
            substriterator i= *this;
            iterator::operator++();
            return i;
        }
    };
};
typedef boost::shared_ptr<IndexSection> IndexSection_ptr;

// todo: FilesSection
// todo: GxxSection

class VdwFile : public Section {

    RootSection_ptr _root;
    typedef std::map<std::string,Section_ptr> sectionmap;
    sectionmap _sections;

    uint32_t _cplen;

    ReadWriter_ptr makevdwreader(uint32_t ofs, uint32_t size)
    {
        static const std::vector<uint8_t> vdwkey= {'d', 'w', 'v' };
        return ReadWriter_ptr(new xorreader(vdwkey, getptr(ofs), getptr(ofs)+size));
    }
public:
    VdwFile(const std::vector<uint8_t>& M, const uint8_t* first, const uint8_t* last)
        : Section(M, 0, first, last), _cplen(0)
    {
        ReadWriter_ptr x= makevdwreader(0x2a, 20);

        setname("vdwfile");
        setdesc("vdwfile");

        usage(0x2a, 20, "indexptrs");

        uint32_t unk0=  x->read32le();
        uint32_t troot= x->read32le();
        uint32_t proot= x->read32le();
        uint32_t sroot= x->read32le();
        _cplen= x->read32le();

        usage(0x3e, 2*_cplen, "plain copyright");
        usage(0x3e + 2*_cplen, 2*_cplen, "xorred copyright");

        printf("root: %d, %x, @%x:%x, copyrightlen=%x\n", unk0, troot, proot, sroot, _cplen);

        usage(proot, sroot, "root section");
        _root= RootSection_ptr(new RootSection(M,  troot, getptr(proot), getptr(proot+sroot)));

        printf("name: %s\n", _root->name().c_str());
        printf("desc: %s\n", _root->desc().c_str());

        uint32_t bofs, blen, btype;

        unsigned i=0;
        while (_root->getsection(i++, &bofs, &blen, &btype)) {
            Section_ptr s;
            switch (btype>>16) {
//              case 1:
//                  s.reset(new InfoSection(M, btype, getptr(bofs), getptr(bofs+blen)));
//                  break;
                case 2:
                    s.reset(new BlobSection(M, btype, getptr(bofs), getptr(bofs+blen)));
                    break;
                case 3:
                    s.reset(new IndexSection(M, btype, getptr(bofs), getptr(bofs+blen)));
                    break;
                // 4 == root section
//              case 5:
//                  s.reset(new SearchSection(M, btype, getptr(bofs), getptr(bofs+blen)));
//                  break;
                default:
                    printf("not handling section %08x/%08x: t%08x\n", bofs, blen, btype);
            }
            if (s) {
                usage(bofs, blen, stringformat("%08x: %s", btype, s->name().c_str()));
                printf("%08x %08x %08x %s\n", btype, bofs, blen, s->name().c_str());
                _sections.insert(sectionmap::value_type(s->name(), s));
            }
            else {
                usage(bofs, blen, stringformat("%08x: ?", btype));
            }
        }
    }
    void dumpblobs()
    {
        std::for_each(_sections.begin(), _sections.end(), [](const sectionmap::value_type& i) {
            BlobSection_ptr blob= boost::dynamic_pointer_cast<BlobSection>(i.second);
            if (blob)
                blob->dumpinfo();
        });
    }
    void dumpusage()
    {
        Section::dumpusage();
        _root->dumpusage();
        std::for_each(_sections.begin(), _sections.end(), [](const sectionmap::value_type& i) {
            i.second->dumpusage();
        });
    }
    void save(const std::string& path)
    {
        saveall(path);
        _root->saveall(path);
        std::for_each(_sections.begin(), _sections.end(), [&path](const sectionmap::value_type& i) {
            i.second->saveall(path);
        });
    }
    virtual void verifysection()
    {
        std::string copyright= ToString(std::Wstring((WCHAR*)getptr(0x3e), ((WCHAR*)getptr(0x3e))+_cplen));

        ReadWriter_ptr cpr= makexorreader(2*_cplen+0x3e, 2*_cplen);

        std::Wstring cp2;
        cpr->readutf16le(cp2, _cplen);

        if (ToString(cp2)!=copyright) {
            printf("copyright strings don't match\n");
            throw "error";
        }
        printf("%s\n", copyright.c_str());

        std::for_each(_sections.begin(), _sections.end(), [](const sectionmap::value_type& i) {
            i.second->verify();
        });
    }

    IndexSection_ptr idx(const std::string& name) 
    {
        auto i= _sections.find(name);
        if (i==_sections.end())
            throw "index not found";
        IndexSection_ptr p= boost::dynamic_pointer_cast<IndexSection>(i->second);
        if (!p)
            throw "name does not point to index";
        return p;
    }
    BlobSection_ptr blob(const std::string& name) 
    {
        auto i= _sections.find(name);
        if (i==_sections.end())
            throw "blob not found";
        BlobSection_ptr p= boost::dynamic_pointer_cast<BlobSection>(i->second);
        if (!p)
            throw "name does not point to blob";
        return p;
    }
    void searchindex(const std::string& name, const std::string& word)
    {
        std::vector<uint64_t> laps;
        HiresTimer t;
        auto ix= idx(name);

        printf("*** testing %s - %s search\n", name.c_str(), ((ix->type()&0xfffffff0)==0x00030200) ? "substr" : "string");

        laps.push_back(t.lap());

        auto s= ((ix->type()&0xfffffff0)==0x00030200) ? ix->substrsearch(word) : ix->stringsearch(word);
        laps.push_back(t.lap());
        
        BlobSection_ptr words= blob("idxTrefwoordCookieHtmlheadword");
        laps.push_back(t.lap());

        for (auto const&i : s)
            printf("%08x : %s\n", i, words->getitem(i).c_str());
        printf("\n");

        laps.push_back(t.lap());

        printf("laps: %lld  %lld  %lld  %lld\n", laps[0], laps[1], laps[2], laps[3]);
    }
    void testidx(const std::string& txt)
    {
        searchindex("idxTrefwoordLemma" ,txt);
        searchindex("idxFulltextLemma"  ,txt);
        searchindex("idxWoordvormLemma" ,txt);
        searchindex("idxBoeklemidLemma" ,txt);
        searchindex("idxBoektrefLemma"  ,txt);
    }
    // fulltext substring -> idxFulltextLemma
    // keyword substring -> idxTrefwoordLemma
};

int main(int argc, char**argv)
{
    std::string lang;
    std::vector<std::string> words;
    bool wantverify= false;
    bool wantusage= false;
    std::string savepath;

    for (int i=1 ; i<argc ; i++)
    {
        if (argv[i][0]=='-') switch(argv[i][1]) {
            case 'V': wantverify= true; break;
            case 'U': wantusage= true; break;
            case 'w': savepath= getstrarg(argv, i, argc); break;
            default:
                  printf("Usage: vdwreader [-V] [-U] [-w path] <dn|en|fn|nd|ne|nf|nn> words...\n");
        }
        else if (lang.empty())
            lang= argv[i];
        else
            words.push_back(argv[i]);
    }

    auto ent= keymap.find(lang);
    if (ent==keymap.end()) {
        printf("unknown language\n");
        return 1;
    }

    try {
    MmapReader r(getpath(lang), MmapReader::readonly);

    if (r.size()<16) {
        printf("vdw too short\n");
        return 1;
    }
    std::vector<uint8_t> M(256);
        
    calcmd5key(ent->second, &M[0]);

    VdwFile vdw(M, r.begin(), r.end());

    if (wantverify)
        vdw.verify();
    if (wantusage)
        vdw.dumpusage();
    if (!savepath.empty())
        vdw.save(savepath);

    for (unsigned i=0 ; i<words.size() ; i++)
    {
        printf("searching '%s'\n", words[i].c_str());
        vdw.testidx(words[i]);
    }

    //vdw.dumpblobs();

    }
    catch(const char*msg)
    {
        printf("E: %s\n", msg);
    }
    printf("done\n");
    return 0;
}

