from owlready2 import *
import time
import csv
owlready2.JAVA_EXE ="C:/Users/borja/Desktop/Terminar TFG/TFG/Protege-5.5.0/jre/bin/javaw.exe"

def poblar():
    
    start_time = time.time()

    onto = get_ontology("ontologia_vulnerabilidades.owl").load()

    f_empresas_paises = open("population_empresas_paises.csv")
    reader_empresas_paises = csv.reader(f_empresas_paises)
    next(reader_empresas_paises)

    f_population = open("population_individuals.csv")
    reader_population = csv.reader(f_population)
    next(reader_population)

    #CARGAMOS LOS INDIVIDUOS DE EMPRESAS Y PAISES

    with onto:
        for row1 in reader_empresas_paises:
            Empresas,Paises = row1
            
            #CREA LAS EMPRESAS
            #CREA LOS PAISES
                        
            individual_empresa = onto.Empresa_afectada(Empresas)
            individual_paises = onto.Pais(Paises)

    onto.save("ontologia_vulnerabilidades.owl")

    #CARGAMOS LOS CVE Y ATT

    with onto:
        for row2 in reader_population:
            ID_CVE,Confidencialidad,Integridad,Disponibilidad,Economico,Ideologico,Difamacion,Desafio_Intelectual,Destruccion,Secuestro,Obtencion,Ano_CVE,Identificador_CVE,genera,Tipo_de_vulnerabilidad,ID_ATT,Ano_ATT,Identificador_ATT,afectaAlPais,afectaLaEmpresa,Capa_del_ataque,Tipo_de_producto_afectado = row2

            #CREA LOS ATT

            individual_att = onto.Ataque(ID_ATT)

            if Ano_ATT:
                individual_att.Ano = int(Ano_ATT)

            if Identificador_ATT:
                individual_att.Identificador = int(Identificador_ATT)

            if afectaLaEmpresa:
                genera_ind_empresa = onto.Empresa_afectada(str(afectaLaEmpresa))
                individual_att.afectaLaEmpresa = genera_ind_empresa    
            
            if afectaAlPais:
                genera_ind_pais = onto.Pais(str(afectaAlPais))
                individual_att.atacaAlPais = genera_ind_pais

            if Capa_del_ataque:
                tipo_capa = str(Capa_del_ataque)
                tipo_onto_capa = getattr(onto, tipo_capa)
                individual_att.is_a.append(tipo_onto_capa)

            if Tipo_de_producto_afectado:
                tipo_prod = str(Tipo_de_producto_afectado)
                tipo_onto_prod = getattr(onto, tipo_prod)
                individual_att.is_a.append(tipo_onto_prod)


            #CREA LOS CVE

            individual_cve = onto.Vulnerabilidad(ID_CVE)

            if Confidencialidad:
                individual_cve.Confidencialidad = Confidencialidad

            if Integridad:
                individual_cve.Integridad = Integridad

            if Disponibilidad:
                individual_cve.Disponibilidad = Disponibilidad

            if Economico:
                individual_cve.Economico = Economico

            if Ideologico:
                individual_cve.Ideologico = Ideologico

            if Difamacion:
                individual_cve.Difamacion = Difamacion

            if Desafio_Intelectual:
                individual_cve.Desafio_Intelectual = Desafio_Intelectual

            if Destruccion:
                individual_cve.Destruccion = Destruccion

            if Secuestro:
                individual_cve.Secuestro = Secuestro

            if Obtencion:
                individual_cve.Obtencion = Obtencion

            if Ano_CVE:
                individual_cve.Ano = int(Ano_CVE)

            if Identificador_CVE:
                individual_cve.Identificador = int(Identificador_CVE)

            if genera:
                genera_ind = onto.Ataque(str(genera))
                individual_cve.genera = genera_ind

            if Tipo_de_vulnerabilidad:
                tipo_ind = str(Tipo_de_vulnerabilidad)
                tipo_onto_ind = getattr(onto, tipo_ind)
                individual_cve.is_a.append(tipo_onto_ind)

    onto.save("ontologia_vulnerabilidades.owl")

    #EJECUTAMOS EL RAZONADOR Y GUARDAMOS LA ONTOLOGIA DE NUEVO

    with onto:
    
        sync_reasoner()

    onto.save("ontologia_vulnerabilidades.owl")


    with onto:
    
        default_world.sparql("""
            PREFIX o: <http://www.semanticweb.org/borja/ontologies/2022/ontologia_vulnerabilidades#>
            INSERT { ?cve a o:12_horas.}
            WHERE  {{?cve a o:Muy_alta. ?cve a o:Code_Execution.} UNION 
                {?cve a o:Muy_alta. ?cve a o:Memory_Corruption.} UNION
                {?cve a o:Muy_alta. ?cve a o:Overflow.} UNION
                {?cve a o:Alta. ?cve a o:Code_Execution.} UNION
                {?cve a o:Alta. ?cve a o:Memory_Corruption.} UNION
                {?cve a o:Alta. ?cve a o:Overflow.}}
        """)

        default_world.sparql("""
            PREFIX o: <http://www.semanticweb.org/borja/ontologies/2022/ontologia_vulnerabilidades#>
            INSERT { ?cve a o:24_horas.}
            WHERE  {{?cve a o:Muy_alta. ?cve a o:Gain_Information.} UNION 
                {?cve a o:Muy_alta. ?cve a o:Gain_Privileges.} UNION
                {?cve a o:Muy_alta. ?cve a o:XSS.} UNION
                {?cve a o:Alta. ?cve a o:Gain_Information.} UNION
                {?cve a o:Alta. ?cve a o:Gain_Privileges.} UNION
                {?cve a o:Alta. ?cve a o:XSS.} UNION
                {?cve a o:Normal. ?cve a o:Code_Execution.} UNION
                {?cve a o:Normal. ?cve a o:Memory_Corruption.} UNION
                {?cve a o:Normal. ?cve a o:Overflow.}}
        """)

        default_world.sparql("""
            PREFIX o: <http://www.semanticweb.org/borja/ontologies/2022/ontologia_vulnerabilidades#>
            INSERT { ?cve a o:3_dias.}
            WHERE  {{?cve a o:Muy_alta. ?cve a o:DoS.} UNION 
                {?cve a o:Muy_alta. ?cve a o:Http_Response_Splitting.} UNION
                {?cve a o:Muy_alta. ?cve a o:Sql_injection.} UNION
                {?cve a o:Alta. ?cve a o:DoS.} UNION
                {?cve a o:Alta. ?cve a o:Http_Response_Splitting.} UNION
                {?cve a o:Alta. ?cve a o:Sql_injection.} UNION
                {?cve a o:Normal. ?cve a o:Gain_Information.} UNION
                {?cve a o:Normal. ?cve a o:Gain_Privileges.} UNION
                {?cve a o:Normal. ?cve a o:XSS.} UNION
                {?cve a o:Baja. ?cve a o:Code_Execution.} UNION
                {?cve a o:Baja. ?cve a o:Memory_Corruption.} UNION
                {?cve a o:Baja. ?cve a o:Overflow.} UNION
                {?cve a o:Muy_baja. ?cve a o:Code_Execution.} UNION
                {?cve a o:Muy_baja. ?cve a o:Memory_Corruption.} UNION
                {?cve a o:Muy_baja. ?cve a o:Overflow.}}
        """)

        default_world.sparql("""
            PREFIX o: <http://www.semanticweb.org/borja/ontologies/2022/ontologia_vulnerabilidades#>
            INSERT { ?cve a o:15_dias.}
            WHERE  {{?cve a o:Normal. ?cve a o:DoS.} UNION 
                {?cve a o:Normal. ?cve a o:Http_Response_Splitting.} UNION
                {?cve a o:Normal. ?cve a o:Sql_injection.} UNION
                {?cve a o:Baja. ?cve a o:Gain_Information.} UNION
                {?cve a o:Baja. ?cve a o:Gain_Privileges.} UNION
                {?cve a o:Baja. ?cve a o:XSS.} UNION
                {?cve a o:Muy_baja. ?cve a o:Gain_Information.} UNION
                {?cve a o:Muy_baja. ?cve a o:Gain_Privileges.} UNION
                {?cve a o:Muy_baja. ?cve a o:XSS.}}
        """)

        default_world.sparql("""
            PREFIX o: <http://www.semanticweb.org/borja/ontologies/2022/ontologia_vulnerabilidades#>
            INSERT { ?cve a o:30_dias.}
            WHERE  {{?cve a o:Baja. ?cve a o:DoS.} UNION 
                {?cve a o:Baja. ?cve a o:Http_Response_Splitting.} UNION
                {?cve a o:Baja. ?cve a o:Sql_injection.} UNION
                {?cve a o:Muy_baja. ?cve a o:DoS.} UNION
                {?cve a o:Muy_baja. ?cve a o:Http_Response_Splitting.} UNION
                {?cve a o:Muy_baja. ?cve a o:Sql_injection.}}
        """)

    onto.save("ontologia_vulnerabilidades.owl")


    #DEVOLVEMOS EL TIEMPO TOTAL QUE TARDA EN CREAR Y EJECUTAR EL RAZONADOR DE LA ONTOLOGIA

    end_time = time.time()

    total_time = end_time-start_time

    return total_time

print(poblar())
