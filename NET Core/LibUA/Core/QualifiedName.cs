
// Type: LibUA.Core.QualifiedName



namespace LibUA.Core
{
    public struct QualifiedName
    {
        public ushort NamespaceIndex;
        public string Name;

        public QualifiedName(string Name)
        {
            this.NamespaceIndex = 0;
            this.Name = Name;
        }

        public QualifiedName(ushort NamespaceIndex, string Name)
        {
            this.NamespaceIndex = NamespaceIndex;
            this.Name = Name;
        }

        public override bool Equals(object obj)
        {
            return obj is QualifiedName qualifiedName ? this.ToString() == qualifiedName.ToString() : base.Equals(obj);
        }

        public override int GetHashCode()
        {
            return this.ToString().GetHashCode();
        }

        public override string ToString()
        {
            return string.Format("[{0}] {1}", NamespaceIndex, this.Name ?? "");
        }
    }
}
