namespace LibUA
{
    namespace Core
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
                if (obj is QualifiedName)
                {
                    return ToString() == ((QualifiedName)obj).ToString();
                }

                return base.Equals(obj);
            }

            public override int GetHashCode()
            {
                return ToString().GetHashCode();
            }

            public override string ToString()
            {
                return string.Format("[{0}] {1}", NamespaceIndex, Name ?? "");
            }
        }
    }
}
