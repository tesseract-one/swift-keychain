Pod::Spec.new do |s|
  s.name             = 'Keychain'
  s.version          = '0.0.1'
  s.summary          = 'Multi-network keychain realization for Swift'

  s.description      = <<-DESC
Swift library for working with private keys and signing.
                       DESC

  s.homepage         = 'https://github.com/tesseract.1/swift-keychain'

  s.license          = { :type => 'Apache 2.0', :file => 'LICENSE' }
  s.author           = { 'Tesseract Systems, Inc.' => 'info@tesseract.one' }
  s.source           = { :git => 'https://github.com/tesseract.1/swift-keychain.git', :tag => s.version.to_s }
  s.social_media_url = 'https://twitter.com/tesseract_io'

  s.ios.deployment_target = '8.0'
  
  s.source_files = 'Sources/Keychain/**/*.swift'

  s.dependency 'CKMnemonic', '~> 0.1'
  s.dependency 'BigInt', '~> 3.1'
  s.dependency 'CryptoSwift', '~> 0.15'
  s.dependency 'secp256k1.swift', '~> 0.1'
end
