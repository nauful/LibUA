
// Type: LibUA.Core.LocalizedText



namespace LibUA.Core
{
    public class LocalizedText
    {
        public string Locale { get; set; }

        public string Text { get; set; }

        public LocalizedText(string Text)
        {
            this.Locale = string.Empty;
            this.Text = Text;
        }

        public LocalizedText(string Locale, string Text)
        {
            this.Locale = Locale;
            this.Text = Text;
        }

        public override string ToString()
        {
            return string.Format("[{0}] {1}", Locale, Text);
        }
    }
}
