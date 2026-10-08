package inspect

import "strconv"

// ibanLength is the length of an IBAN per country (SWIFT registry).
var ibanLength = map[[2]byte]int{
	{'A', 'D'}: 24, {'A', 'E'}: 23, {'A', 'L'}: 28, {'A', 'T'}: 20, {'A', 'Z'}: 28, {'B', 'A'}: 20, {'B', 'E'}: 16,
	{'B', 'G'}: 22, {'B', 'H'}: 22, {'B', 'R'}: 29, {'B', 'Y'}: 28, {'C', 'H'}: 21, {'C', 'R'}: 22, {'C', 'Y'}: 28,
	{'C', 'Z'}: 24, {'D', 'E'}: 22, {'D', 'K'}: 18, {'D', 'O'}: 28, {'E', 'E'}: 20, {'E', 'G'}: 29, {'E', 'S'}: 24,
	{'F', 'I'}: 18, {'F', 'O'}: 18, {'F', 'R'}: 27, {'G', 'B'}: 22, {'G', 'E'}: 22, {'G', 'I'}: 23, {'G', 'L'}: 18,
	{'G', 'R'}: 27, {'G', 'T'}: 28, {'H', 'R'}: 21, {'H', 'U'}: 28, {'I', 'E'}: 22, {'I', 'L'}: 23, {'I', 'Q'}: 23,
	{'I', 'S'}: 26, {'I', 'T'}: 27, {'J', 'O'}: 30, {'K', 'W'}: 30, {'K', 'Z'}: 20, {'L', 'B'}: 28, {'L', 'C'}: 32,
	{'L', 'I'}: 21, {'L', 'T'}: 20, {'L', 'U'}: 20, {'L', 'V'}: 21, {'L', 'Y'}: 25, {'M', 'C'}: 27, {'M', 'D'}: 24,
	{'M', 'E'}: 22, {'M', 'K'}: 19, {'M', 'R'}: 27, {'M', 'T'}: 31, {'M', 'U'}: 30, {'N', 'L'}: 18, {'N', 'O'}: 15,
	{'P', 'K'}: 24, {'P', 'L'}: 28, {'P', 'S'}: 29, {'P', 'T'}: 25, {'Q', 'A'}: 29, {'R', 'O'}: 24, {'R', 'S'}: 22,
	{'S', 'A'}: 24, {'S', 'C'}: 31, {'S', 'E'}: 24, {'S', 'I'}: 19, {'S', 'K'}: 24, {'S', 'M'}: 27, {'S', 'T'}: 25,
	{'S', 'V'}: 28, {'T', 'L'}: 23, {'T', 'N'}: 24, {'T', 'R'}: 26, {'U', 'A'}: 29, {'V', 'A'}: 22, {'V', 'G'}: 24,
	{'X', 'K'}: 20,
}

const maxIBAN = 34

// matchIBAN recognises an IBAN: country code, length for that country, groups
// of four optionally separated by a space or hyphen, and a valid mod-97
// checksum.
func matchIBAN(t string, i int) (hit, bool) {
	if !boundaryBefore(t, i) || i+4 > len(t) {
		return hit{}, false
	}
	if !isLetter(t[i]) || !isLetter(t[i+1]) || !isDigit(t[i+2]) || !isDigit(t[i+3]) {
		return hit{}, false
	}
	want := ibanLength[[2]byte{upper(t[i]), upper(t[i+1])}]
	if want == 0 {
		return hit{}, false
	}
	var buf [maxIBAN]byte
	n, j := 0, i
	for j < len(t) && n < want {
		c := t[j]
		switch {
		case isAlnum(c):
			buf[n] = upper(c)
			n++
			j++
		case (c == ' ' || c == '-') && n > 0 && n%4 == 0 && j+1 < len(t) && isAlnum(t[j+1]):
			j++
		default:
			return hit{}, false
		}
	}
	if n != want || !boundaryAfter(t, j) || !ibanChecksum(buf[:n]) {
		return hit{}, false
	}
	return hit{start: i, end: j, canon: string(buf[:n])}, true
}

// ibanChecksum is the ISO 7064 mod-97-10 check: move the first four characters
// to the end, read letters as 10..35, the remainder must be 1.
func ibanChecksum(iban []byte) bool {
	rem := 0
	feed := func(c byte) {
		if isDigit(c) {
			rem = (rem*10 + int(c-'0')) % 97
		} else {
			rem = (rem*100 + int(c-'A') + 10) % 97
		}
	}
	for _, c := range iban[4:] {
		feed(c)
	}
	for _, c := range iban[:4] {
		feed(c)
	}
	return rem == 1
}

// matchCard recognises a payment card number: 13 to 19 digits in groups
// separated by single spaces or hyphens, a plausible issuer prefix and length,
// and a valid Luhn checksum.
func matchCard(t string, i int) (hit, bool) {
	if !boundaryBefore(t, i) {
		return hit{}, false
	}
	var d [19]byte
	n, j := 0, i
	for j < len(t) {
		c := t[j]
		if isDigit(c) {
			if n == len(d) {
				return hit{}, false
			}
			d[n] = c
			n++
			j++
		} else if (c == ' ' || c == '-') && n > 0 && j+1 < len(t) && isDigit(t[j+1]) {
			j++
		} else {
			break
		}
	}
	if n < 13 || !boundaryAfter(t, j) || !cardPrefixOK(d[:n]) || !luhn(d[:n]) {
		return hit{}, false
	}
	return hit{start: i, end: j, canon: string(d[:n])}, true
}

func luhn(d []byte) bool {
	sum := 0
	for k, alt := len(d)-1, false; k >= 0; k-- {
		v := int(d[k] - '0')
		if alt {
			if v *= 2; v > 9 {
				v -= 9
			}
		}
		sum += v
		alt = !alt
	}
	return sum%10 == 0
}

// cardPrefixOK keeps numbers whose first digits and length belong to a card
// scheme (Visa, Mastercard, American Express, Discover, UnionPay, JCB, Diners):
// a Luhn-valid number alone is a 1 in 10 coincidence for any long number.
func cardPrefixOK(d []byte) bool {
	n := len(d)
	num := func(k int) int { v, _ := strconv.Atoi(string(d[:k])); return v }
	switch {
	case d[0] == '4':
		return n == 13 || n == 16 || n == 19
	case num(2) == 34 || num(2) == 37:
		return n == 15
	case num(2) >= 51 && num(2) <= 55, num(4) >= 2221 && num(4) <= 2720:
		return n == 16
	case num(2) == 62 || num(2) == 65 || num(4) == 6011 || num(3) >= 644 && num(3) <= 649:
		return n >= 16 && n <= 19
	case num(4) >= 3528 && num(4) <= 3589:
		return n >= 16 && n <= 19
	case num(2) == 36 || num(2) == 38 || num(3) >= 300 && num(3) <= 305:
		return n >= 14 && n <= 19
	}
	return false
}

// matchNIR recognises a French social security number (NIR): 13 characters
// (sex, year, month, département, commune, order) and a two-digit key equal to
// 97 - (the first 13 digits mod 97), with Corsica's 2A/2B counted as 19/18.
// Single spaces or dots between characters are tolerated.
func matchNIR(t string, i int) (hit, bool) {
	if !boundaryBefore(t, i) {
		return hit{}, false
	}
	var c [15]byte
	n, j := 0, i
	for j < len(t) && n < len(c) {
		b := t[j]
		switch {
		case isDigit(b), (b == 'A' || b == 'B' || b == 'a' || b == 'b') && (n == 5 || n == 6):
			c[n] = upper(b)
			n++
			j++
		case (b == ' ' || b == '.') && n > 0 && j+1 < len(t) && isAlnum(t[j+1]):
			j++
		default:
			return hit{}, false
		}
	}
	if n != len(c) || !boundaryAfter(t, j) || !nirValid(c) {
		return hit{}, false
	}
	return hit{start: i, end: j, canon: string(c[:])}, true
}

func nirValid(c [15]byte) bool {
	month := int(c[3]-'0')*10 + int(c[4]-'0')
	validMonth := month >= 1 && month <= 12 || month == 20 || month >= 30 && month <= 42 || month >= 50
	if !validMonth {
		return false
	}
	body := make([]byte, 0, 13)
	body = append(body, c[:5]...)
	switch {
	case c[5] == '2' && c[6] == 'A':
		body = append(body, '1', '9')
	case c[5] == '2' && c[6] == 'B':
		body = append(body, '1', '8')
	case isDigit(c[5]) && isDigit(c[6]):
		body = append(body, c[5], c[6])
	default:
		return false
	}
	body = append(body, c[7:13]...)
	num, err := strconv.ParseInt(string(body), 10, 64)
	if err != nil {
		return false
	}
	key := int(c[13]-'0')*10 + int(c[14]-'0')
	return key == 97-int(num%97)
}

// matchPhone recognises international numbers (+ and 8 to 15 digits, with
// spaces, dots, hyphens or parentheses between them) and French national
// numbers (0 then 1-9, ten digits in all). Numbers in other national formats
// are not recognised.
func matchPhone(t string, i int) (hit, bool) {
	if !boundaryBefore(t, i) {
		return hit{}, false
	}
	// A group inside a longer run of numbers (the tail of a social security
	// number or an IBAN) is not a phone number.
	if i >= 2 && (t[i-1] == ' ' || t[i-1] == '.' || t[i-1] == '-') && isDigit(t[i-2]) {
		return hit{}, false
	}
	international := t[i] == '+'
	var d [16]byte
	n, j, end, seps := 0, i, i, 0
	if international {
		j++
	}
	for j < len(t) {
		if !international && n == 10 {
			break // a national number has ten digits; what follows is not part of it
		}
		c := t[j]
		if isDigit(c) {
			if n == len(d) {
				return hit{}, false
			}
			d[n] = c
			n++
			j++
			end, seps = j, 0
			continue
		}
		isSep := c == ' ' || c == '.' || c == '-'
		if international {
			isSep = isSep || c == '(' || c == ')'
		}
		if !isSep || n == 0 || seps >= 2 {
			break
		}
		seps++
		j++
	}
	if !boundaryAfter(t, end) {
		return hit{}, false
	}
	if international {
		if n < 8 || n > 15 {
			return hit{}, false
		}
		return hit{start: i, end: end, canon: "+" + string(d[:n]), confidence: 0.85}, true
	}
	if n != 10 || d[0] != '0' || d[1] == '0' {
		return hit{}, false
	}
	return hit{start: i, end: end, canon: "+33" + string(d[1:n]), confidence: 0.7}, true
}

// matchIPv4 recognises a dotted-quad address that is not part of a longer
// dotted number (a version string, an OID).
func matchIPv4(t string, i int) (hit, bool) {
	if i > 0 && (isAlnum(t[i-1]) || t[i-1] == '.' && i > 1 && isDigit(t[i-2])) {
		return hit{}, false
	}
	j := i
	for octet := 0; octet < 4; octet++ {
		if octet > 0 {
			if j >= len(t) || t[j] != '.' {
				return hit{}, false
			}
			j++
		}
		start, v := j, 0
		for j < len(t) && isDigit(t[j]) && j-start < 3 {
			v = v*10 + int(t[j]-'0')
			j++
		}
		if j == start || v > 255 || j-start > 1 && t[start] == '0' {
			return hit{}, false
		}
	}
	if j < len(t) && (isAlnum(t[j]) || t[j] == '.' && j+1 < len(t) && isDigit(t[j+1])) {
		return hit{}, false
	}
	return hit{start: i, end: j}, true
}
