import java.util.Collections;
import java.util.List;
import java.util.Random;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import java.util.stream.Stream;

public class Sample {
    public static void main(String[] args) {
        String password = generateSecureRandomPassword();
        String passwordBlock = """
                               <input
                                    id='password'
                                    type='password'
                                    placeholder='%s'
                                    required
                               />
                               """.formatted(password);
        System.out.println(passwordBlock);
    }

    public static Stream<Character> getRandomSpecialChars(int count) {
        return getRandomCharacters(count, '!', '-');
    }

    public static Stream<Character> getRandomAlphabets(int count, boolean includesUppercase) {
        return getRandomCharacters(count, 'a', 'z');
    }

    public static Stream<Character> getRandomNumbers(int count) {
        return getRandomCharacters(count, '0', '9');
    }

    private static Stream<Character> getRandomCharacters(int count, int leftMargin, int rightMargin) {
        Random random = new Random();
        IntStream specialChars = random.ints(count, leftMargin, rightMargin);
        return specialChars.mapToObj(data -> (char) data);
    }

    public static String generateSecureRandomPassword() {
        Stream<Character> pwdStream = Stream.concat(getRandomNumbers(2),
                Stream.concat(getRandomSpecialChars(2),
                        Stream.concat(getRandomAlphabets(2, true), getRandomAlphabets(4, false))));
        List<Character> charList = pwdStream.collect(Collectors.toList());
        Collections.shuffle(charList);
        return charList.stream()
                .collect(StringBuilder::new, StringBuilder::append, StringBuilder::append)
                .toString();
    }
	
	
}

    public static String generateSecureRandomPassword() {
        Stream<Character> pwdStream = Stream.concat(getRandomNumbers(2),
                Stream.concat(getRandomSpecialChars(2),
                        Stream.concat(getRandomAlphabets(2, true), getRandomAlphabets(4, false))));
        List<Character> charList = pwdStream.collect(Collectors.toList());
        Collections.shuffle(charList);
        return charList.stream()
                .collect(StringBuilder::new, StringBuilder::append, StringBuilder::append)
                .toString();
				
				    public static String generateSecureRandomPassword() {
        Stream<Character> pwdStream = Stream.concat(getRandomNumbers(2),
                Stream.concat(getRandomSpecialChars(2),
                        Stream.concat(getRandomAlphabets(2, true), getRandomAlphabets(4, false))));
        List<Character> charList = pwdStream.collect(Collectors.toList());
        Collections.shuffle(charList);
        return charList.stream()
                .collect(StringBuilder::new, StringBuilder::append, StringBuilder::append)
                .toString();