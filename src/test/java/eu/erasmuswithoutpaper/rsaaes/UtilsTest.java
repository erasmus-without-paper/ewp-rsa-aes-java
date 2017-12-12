package eu.erasmuswithoutpaper.rsaaes;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.Test;

import eu.erasmuswithoutpaper.rsaaes.Utils;

public class UtilsTest extends TestBase {

  @Test
  public void testAddLineBreaks() {
    assertThat(Utils.addLineBreaks("abc", 1)).isEqualTo("a\nb\nc");
    assertThat(Utils.addLineBreaks("abc", 2)).isEqualTo("ab\nc");
    assertThat(Utils.addLineBreaks("abc", 3)).isEqualTo("abc");
    assertThat(Utils.addLineBreaks("abc", 4)).isEqualTo("abc");

    assertThat(Utils.addLineBreaks("a", 1)).isEqualTo("a");
    assertThat(Utils.addLineBreaks("a", 2)).isEqualTo("a");

    assertThat(Utils.addLineBreaks("", 1)).isEqualTo("");
    assertThat(Utils.addLineBreaks("", 2)).isEqualTo("");
  }

}
