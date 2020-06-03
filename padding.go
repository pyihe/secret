package secret

import "bytes"

const (
	PaddingTypeNoPadding paddingType = iota //接口不对数据进行填充处理，需要自己手动填充(加解密双方自行定义填充方式)
	PaddingTypePKCS5                        //PKCS5
	PaddingTypePKCS7                        //PKCS7
	PaddingTypeZeros                        //用0作为填充
)

type (
	paddingType uint
)

func padding(data []byte, blockSize int, pt paddingType) []byte {
	switch pt {
	case PaddingTypePKCS7:
		fallthrough
	case PaddingTypePKCS5:
		return paddingWithPKCS5(data, blockSize)
	case PaddingTypeZeros:
		return paddingWithZeros(data, blockSize)
	default:
		return data
	}
}

func unPadding(data []byte, pt paddingType) []byte {
	switch pt {
	case PaddingTypePKCS7:
		fallthrough
	case PaddingTypePKCS5:
		return unPaddingWithPKCS5(data)
	case PaddingTypeZeros:
		return unPaddingWithZeros(data)
	default:
		return data
	}
}

func paddingWithPKCS5(data []byte, blockSize int) []byte {
	//需要填充的值以及数量
	padding := blockSize - len(data)%blockSize
	//组装填充值([]byte)
	var paddingData = []byte{byte(padding)}
	paddingData = bytes.Repeat(paddingData, padding)
	//append填充
	data = append(data, paddingData...)
	return data
}

func unPaddingWithPKCS5(data []byte) []byte {
	padding := int(data[len(data)-1])
	return data[:len(data)-padding]
}

func paddingWithZeros(data []byte, blockSize int) []byte {
	//需要填充的值以及数量
	padding := blockSize - len(data)%blockSize
	//组装填充值([]byte)
	var paddingData = []byte{0}
	paddingData = bytes.Repeat(paddingData, padding)
	//append填充
	data = append(data, paddingData...)
	return data
}

func unPaddingWithZeros(data []byte) []byte {
	return bytes.TrimFunc(data, func(r rune) bool {
		return r == 0
	})
}