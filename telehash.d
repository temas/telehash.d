module telehash;

import std.stdio;
import std.socket;
import std.string;
import std.format;
import std.conv;
import libevent;
import json;
import std.base64;
import std.bitmanip;
import std.container;
import deimos.openssl.pem;
import deimos.openssl.err;
import deimos.openssl.aes;
import deimos.openssl.evp;
import cryptopp;
import std.datetime;
import std.array;

class TelehashSwitch {
  Socket[string] sockets;
}

class TelehashListener : Socket {
  this(ref TelehashSwitch ts) {
    telehashSwitch = ts;
  }

  override void handleData(Packet pkt) {
  }

  TelehashSwitch telehashSwitch;
}

class Packet {
  ulong sequence;
  ubyte[] raw;
  ulong rawLength;
  Json json;
  ubyte[] rawBody;

  this() {
    raw = new ubyte[1600];
    json = Json.emptyObject;
  }

  void parse() {
    //writeln("Full buffer: ", raw);
    if (rawLength <= 2) {
      throw new Exception("Packet is too short");
    }

    //ubyte[] raw = pkt.raw;
    ushort jsonLen = raw.read!ushort();
    //writeln("Read len of ", jsonLen, " total is ", rawLength, " in ", raw.length);

    auto jsonStr = raw[0..jsonLen];
    rawBody = raw[jsonLen..rawLength - 2];

    //writeln("json str: ", cast(string)jsonStr);
    //writeln("raw length ", rawBody.length);
    //writeln("raw buffer: ", rawBody);
    json = parseJson(jsonStr); // This is caught up a layer if it throws
    // We have to have a top level object, otherwise it's junk
    if (json.type != Json.Type.Object) {
      throw new Exception("JSON was not an object");
    }
  }

  void encrypt(ubyte[] secret, ubyte[] iv) {
    encrypt(rawBody, secret, iv);
  }

  void encrypt(ubyte[] plaintext, ubyte[] secret, ubyte[] iv) {
    rawBody = new ubyte[plaintext.length];
    aes_256_ctr_encrypt(plaintext.ptr, plaintext.length, rawBody.ptr, secret.ptr, iv.ptr);
  }

  void decrypt(ubyte[] secret, ubyte[] iv) {
    decrypt(rawBody, secret, iv);
  }

  void decrypt(ubyte[] encryptedData, ubyte[] secret, ubyte[] iv) {
    rawBody = new ubyte[encryptedData.length];
    aes_256_ctr_decrypt(encryptedData.ptr, encryptedData.length, rawBody.ptr, secret.ptr, iv.ptr);
  }

  /// Fill raw with the encoded packet
  void encode() {
    string stringifiedJson = json.toString();
    rawLength = 0;
    std.bitmanip.write!ushort(raw, cast(ushort)stringifiedJson.length, rawLength);
    rawLength += 2;
    raw[rawLength..rawLength + stringifiedJson.length] = cast(ubyte[])stringifiedJson;
    rawLength += stringifiedJson.length;
    raw[rawLength..rawLength + rawBody.length] = rawBody;
    rawLength += rawBody.length;
    raw = raw[0..rawLength];
  }
}

struct TelehashSession {
  string sid;
  ulong sequenceStart;
  ulong lastSeenSequence;
  SList!Packet packetBuffer;
}



struct Identity {
  this(ubyte[] publicKey) {
    rsa_keys = rsa_from_public(publicKey.ptr, publicKey.length);
    if (!rsa_keys) {
      throw new Exception("Invalid public key");
    }
  }

  this(string publicKeyPath, string privateKeyPath) {
    rsa_keys = rsa_load_keys(publicKeyPath.toStringz(), privateKeyPath.toStringz());
  }

  string hashname() {
    ubyte[] publicKey = new ubyte[rsa_keys.DERpublicKeyLength()];
    rsa_keys.DERpublicKey(publicKey.ptr, publicKey.length);
    //writefln("HASH KEY %(%02x%)", publicKey);
    ubyte hashedKey[32];
    sha256(publicKey.ptr, publicKey.length, hashedKey.ptr);
    auto hashWriter = appender!string();
    formattedWrite(hashWriter, "%(%02x%)", hashedKey);
    return hashWriter.data;
  }

  cryptopp.RSA rsa_keys;
  Address address;
}

class Socket : UdpSocket {
  void doRead(EvLoop* loop, EventFlags flags) {
    auto pkt = new Packet;

    Address remote;
    pkt.rawLength = receiveFrom(pkt.raw, remote);
    pkt.raw = pkt.raw[0..pkt.rawLength];

    try {
      pkt.parse();
    } catch(Exception E) {
      writeln("Exception parsing packet: ", E);
      delete pkt;
      return;
    }

    //writefln("Incoming isOpen(%d)", isOpen);
    if (!isOpen && (pkt.json["type"].type == Json.Type.Undefined || pkt.json["type"].get!string() != "open")) {
      writeln("Invalid packet, not opened.");
      delete pkt;
      return;
    } else if (!isOpen) {
      // Get the ecc public key and decrypt it
      string open = pkt.json["open"].get!string();
      ubyte[] decoded = Base64.decode(open);

      ubyte[] outKey = new ubyte[identity.rsa_keys.decryptLength(decoded.length)];
      ulong outLength = identity.rsa_keys.decrypt(decoded.ptr, decoded.length, outKey.ptr);
      outKey = outKey[0..outLength];

      //writefln("Key is %d %(%#x %)", outKey.length, outKey);

      // Setup a new diffie-hellman environment and generate ephemeral keys
      ECDH dh = start_ecdh();
      ubyte[] publicKey = new ubyte[dh.publicKeyLength];
        
      // agree on the shared secret
      //writeln("public key length ", dh.publicKeyLength);
      //writeln("Public key ", Base64.encode(dh.publicKey[0..dh.publicKeyLength]));
      ubyte[] secret = new ubyte[dh.agreedValueLength];
      dh.agree(secret.ptr, outKey.ptr);

      //writefln("secret: %(%02x%)", secret);

      // Decrypt the body and build another packet off it
      ubyte iv[16];
      string ivStr = pkt.json.iv.get!string;
      foreach(size_t i; 0..iv.length) {
        iv[i] = ivStr[2*i..2*(i+1)].to!ubyte(16);
      }
      ubyte innerSecret[32];
      cryptopp.sha256(outKey.ptr, outKey.length, innerSecret.ptr);
      //writeln(pkt.rawBody);
      ubyte[] encryptedBody = pkt.rawBody.dup;
      pkt.decrypt(innerSecret, iv);
      //writefln("Decrypted is %(%c %)", cast(char[])pkt.rawBody[2..$]);
      Packet innerPkt = new Packet;
      innerPkt.raw = pkt.rawBody;
      innerPkt.rawLength = pkt.rawBody.length;
      innerPkt.parse();

      // Verify the inner packet has the required members
      if (innerPkt.json["to"].type == Json.Type.Undefined ||
          innerPkt.json["at"].type == Json.Type.Undefined ||
          innerPkt.json["line"].type == Json.Type.Undefined) {
        writeln("Invalid inner open packet, dropping");
        delete innerPkt;
        delete pkt;
        return;
      }

      //writefln("KEY: %(%02x%)", innerPkt.rawBody);
      Identity sender_identity = Identity(innerPkt.rawBody);
      sender_identity.address = remote;

      // Verify the RSA signature in the sig
      //std.stdio.writeln("Encrypted Body: ", encryptedBody.length, " : ", encryptedBody);
      ubyte[] rawSig = Base64.decode(pkt.json["sig"].get!string);
      //writeln("sig: ", rawSig);
      if (!sender_identity.rsa_keys.verify(encryptedBody.ptr, encryptedBody.length, rawSig.ptr, rawSig.length)) {
        writeln("Unable to verify the signature of the open packet.");
        delete innerPkt;
        delete pkt;
        return;
      } else {
        writeln("We agreed!");
      }

      // Send back an open so we can all agree on things
      sendOpen(sender_identity, dh);

      // Get our aes key setup now that we're all set
      // TODO:  Sha256 the line and shared secret
      string inLine = innerPkt.json["line"].get!string;
      //writeln("inline ", inLine);
      for (int i = 0; i < 16; ++i) {
        incomingLine[i] = inLine[2*i..2*(i+1)].to!ubyte(16);
      }
      
      ubyte[] keyMaterial = new ubyte[32 + secret.length];
      keyMaterial[0..secret.length] = secret;
      keyMaterial[$-32..$-16] = outgoingLine;
      keyMaterial[$-16..$] = incomingLine;
      //writefln("KeyMaterial %(%02x %) ", keyMaterial);
      sha256(keyMaterial.ptr, keyMaterial.length, encryptor_key.ptr);

      //writefln("Encryptor key is %(%02x %)", encryptor_key);

      keyMaterial[$-32..$-16] = incomingLine;
      keyMaterial[$-16..$] = outgoingLine;
      sha256(keyMaterial.ptr, keyMaterial.length, decryptor_key.ptr);

      //writefln("Decryptor key is %(%02x %)", decryptor_key);

      isOpen = true;

      return;
    }

    //writeln(pkt.json);
    if (isOpen && pkt.json["type"].type == Json.Type.Undefined && pkt.json["type"].get!string() != "line") {
      writeln("Received non line packet on open socket.");
      delete pkt;
      return;
    }
    // Check if we're on a session and sequenced
    /*
    if (parsedJson["sid"] && parseJson["seq"]) {
      ulong curSequence = parseJson["seq"].uinteger;

    }
    */
    writeln("NORMAL HANDLE ", pkt.json);
    // XXX TODO:  Check the line and discard if mismatched
    string ivStr = pkt.json["iv"].get!string;
    ubyte curIv[16];
    for (int i = 0; i < 16; ++i) {
      curIv[i] = ivStr[2*i..2*(i+1)].to!ubyte(16);
    }
    pkt.decrypt(decryptor_key, curIv);

    //writeln(pkt.rawBody);
    Packet innerPkt = new Packet;
    innerPkt.raw = pkt.rawBody;
    innerPkt.rawLength = pkt.rawBody.length;
    innerPkt.parse();
    writeln("Decrypted packet ", innerPkt.json);

    handleData(pkt);
  }

  void handleData(Packet pkt) {
    // XXX Is there a base impl?
  }

  void sendOpen(Identity to, ECDH dh) {
    Packet pkt = new Packet;

    pkt.json["type"] = "open";
    ubyte[] openEncrypted = new ubyte[to.rsa_keys.encryptLength(dh.publicKeyLength)];
    to.rsa_keys.encrypt(dh.publicKey, dh.publicKeyLength, openEncrypted.ptr);
    pkt.json["open"] = Base64.encode(openEncrypted);
    
    Packet innerPkt = new Packet;
    innerPkt.json["to"] = to.hashname;
    auto currentTime = Clock.currTime();
    innerPkt.json["at"] = currentTime.toUnixTime() * 1000;
    ubyte line[16];
    cryptopp.randomBytes(line.ptr, 16);
    outgoingLine = line;
    auto lineWriter = appender!string();
    formattedWrite(lineWriter, "%(%02x%)", line);
    innerPkt.json["line"] = lineWriter.data;
    ubyte[] publicKey = new ubyte[identity.rsa_keys.DERpublicKeyLength()];
    identity.rsa_keys.DERpublicKey(publicKey.ptr, publicKey.length);
    innerPkt.rawBody = publicKey;

    innerPkt.encode();
    pkt.rawBody = innerPkt.raw;

    ubyte iv[16];
    cryptopp.randomBytes(iv.ptr, 16);
    auto ivWriter = appender!string();
    //writeln(iv);
    formattedWrite(ivWriter, "%(%02x%)", iv);
    pkt.json.iv = ivWriter.data;
    ubyte dhKeyHash[32];
    sha256(dh.publicKey, dh.publicKeyLength, dhKeyHash.ptr);
    pkt.encrypt(dhKeyHash, iv[0..16]);

    ubyte[] sig = new ubyte[identity.rsa_keys.signatureLength];
    identity.rsa_keys.sign(pkt.rawBody.ptr, pkt.rawBody.length, sig.ptr);
    pkt.json["sig"] = Base64.encode(sig);

    pkt.encode();

    sendTo(pkt.raw, to.address);
  }

  @property bool isOpen() { return socketIsOpen; }
  @property bool isOpen(bool value) { return socketIsOpen = value; }

  @property telehash.Identity identity() { return socketIdentity; }
  @property telehash.Identity identity(telehash.Identity value) { return socketIdentity = value; }

private:
  bool socketIsOpen = false;
  telehash.Identity socketIdentity;

  ubyte[32] encryptor_key;
  ubyte[32] decryptor_key;
  ubyte[16] outgoingLine;
  ubyte[16] incomingLine;
}

void main() {
  auto loop = new EvLoop;

  auto serverSocket = new telehash.Socket;
  serverSocket.identity = telehash.Identity("server.pder", "server.der");
  serverSocket.blocking = false;
  serverSocket.bind(new InternetAddress(InternetAddress.ADDR_ANY, 8888));

  loop.addEvent(serverSocket.handle, cast(EventFlags)(EventFlags.EvRead|EventFlags.EvPersist), &serverSocket.doRead);

  writeln("Telehash router started");

  loop.dispatch();
}

