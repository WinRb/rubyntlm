# frozen_string_literal: true

RSpec.describe Net::NTLM do
  let(:passwd) { 'SecREt01' }
  let(:user) { 'user' }
  let(:domain) { 'DOMAIN' }
  let(:challenge) { ['0123456789abcdef'].pack('H*') }
  let(:client_ch) { ['ffffff0011223344'].pack('H*') }

  it 'converts a value to 64-bit LE Integer' do
    expect(described_class.pack_int64le(42)).to eq("\x2A\x00\x00\x00\x00\x00\x00\x00")
  end

  it 'splits a string into an array of slices, 7 chars or less' do
    expect(described_class.split7('HelloWorld!')).to eq(['HelloWo', 'rld!'])
  end

  it 'generates DES keys from the supplied string' do
    first_key = ['52a2516b252a5161'].pack('H*')
    second_key = ['3180010101010101'].pack('H*')
    expect(described_class.gen_keys(passwd.upcase.ljust(14, "\0"))).to eq([first_key, second_key])
  end

  it 'encrypts the string with DES for each key supplied' do
    keys = described_class.gen_keys(passwd.upcase.ljust(14, "\0"))
    first_crypt = ['ff3750bcc2b22412'].pack('H*')
    second_crypt = ['c2265b23734e0dac'].pack('H*')
    expect(described_class.apply_des(Net::NTLM::LM_MAGIC, keys)).to eq([first_crypt, second_crypt])
  end

  it 'generates an lm_hash' do
    expect(described_class.lm_hash(passwd)).to eq(['ff3750bcc2b22412c2265b23734e0dac'].pack('H*'))
  end

  it 'generates an ntlm_hash' do
    expect(described_class.ntlm_hash(passwd)).to eq(['cd06ca7c7e10c99b1d33b7485a2ed808'].pack('H*'))
  end

  it 'generates an ntlmv2_hash' do
    expect(described_class.ntlmv2_hash(user, passwd, domain)).to eq(['04b8e0ba74289cc540826bab1dee63ae'].pack('H*'))
  end

  context 'when a user passes an NTLM hash for pass-the-hash' do
    let(:passwd) { Net::NTLM::EncodeUtil.encode_utf16le('ff3750bcc2b22412c2265b23734e0dac:cd06ca7c7e10c99b1d33b7485a2ed808') }

    it 'returns the correct ntlmv2 hash' do
      expect(described_class.ntlmv2_hash(user, passwd, domain)).to eq(['04b8e0ba74289cc540826bab1dee63ae'].pack('H*'))
    end
  end

  context 'when the username contains non-ASCI characters' do
    let(:user) { 'юзер' }

    it 'returns the correct ntlmv2 hash' do
      expect(described_class.ntlmv2_hash(user, passwd, domain,
                                         { unicode: true })).to eq(['a0f4b914a37faeaee884b6b04a20faf0'].pack('H*'))
    end
  end

  it 'generates an lm_response' do
    args = { lm_hash: described_class.lm_hash(passwd), challenge: challenge }
    expected = ['c337cd5cbd44fc9782a667af6d427c6de67c20c2d3e77c56'].pack('H*')
    expect(described_class.lm_response(args)).to eq(expected)
  end

  it 'generates an ntlm_response' do
    args = { ntlm_hash: described_class.ntlm_hash(passwd), challenge: challenge }
    expected = ['25a98c1c31e81847466b29b2df4680f39958fb8c213a9cc6'].pack('H*')
    expect(described_class.ntlm_response(args)).to eq(expected)
  end

  it 'generates a lvm2_response' do
    args = { ntlmv2_hash: described_class.ntlmv2_hash(user, passwd, domain), challenge: challenge }
    opts = { client_challenge: client_ch }
    expected = ['d6e6152ea25d03b7c6ba6629c2d6aaf0ffffff0011223344'].pack('H*')
    expect(described_class.lmv2_response(args, opts)).to eq(expected)
  end

  describe '.ntlmv2_response' do
    def target_info_blob
      [
        '02000c0044004f004d00410049004e00' \
          '01000c00530045005200560045005200' \
          '0400140064006f006d00610069006e00' \
          '2e0063006f006d000300220073006500' \
          '72007600650072002e0064006f006d00' \
          '610069006e002e0063006f006d000000' \
          '0000'
      ].pack('H*')
    end

    def expected_ntlmv2_response
      [
        'cbabbca713eb795d04c97abc01ee498301010000000000000090d336b734c301' \
          'ffffff00112233440000000002000c0044004f004d00410049004e0001000c00' \
          '5300450052005600450052000400140064006f006d00610069006e002e006300' \
          '6f006d00030022007300650072007600650072002e0064006f006d0061006900' \
          '6e002e0063006f006d000000000000000000'
      ].pack('H*')
    end

    it 'generates a ntlmv2_response' do
      hash = described_class.ntlmv2_hash(user, passwd, domain)
      args = { ntlmv2_hash: hash, challenge: challenge, target_info: target_info_blob }
      opts = { timestamp: 1_055_844_000, client_challenge: client_ch }
      expect(described_class.ntlmv2_response(args, opts)).to eq(expected_ntlmv2_response)
    end
  end

  describe '.ntlm2_session' do
    def ntlm2_session_result
      described_class.ntlm2_session(
        { ntlm_hash: described_class.ntlm_hash(passwd), challenge: challenge },
        { client_challenge: client_ch }
      )
    end

    it 'generates the client challenge response' do
      expect(ntlm2_session_result[0]).to eq(['ffffff001122334400000000000000000000000000000000'].pack('H*'))
    end

    it 'generates the session response' do
      expect(ntlm2_session_result[1]).to eq(['10d550832d12b2ccb79d5ad1f4eed3df82aca4c3681dd455'].pack('H*'))
    end
  end
end
