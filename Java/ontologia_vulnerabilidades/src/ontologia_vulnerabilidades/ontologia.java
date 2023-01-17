package ontologia_vulnerabilidades;
import java.io.File;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.channels.FileChannel;
import org.semanticweb.owlapi.reasoner.OWLReasoner;
import org.semanticweb.owlapi.reasoner.OWLReasonerFactory;
import org.apache.jena.query.Query;
import org.apache.jena.query.QueryExecution;
import org.apache.jena.query.QueryExecutionFactory;
import org.apache.jena.query.QueryFactory;
import org.apache.jena.rdf.model.Model;
import org.apache.jena.rdf.model.ModelFactory;
import org.semanticweb.HermiT.ReasonerFactory;
import org.semanticweb.owlapi.apibinding.OWLManager;
import org.semanticweb.owlapi.model.IRI;
import org.semanticweb.owlapi.model.OWLClassAssertionAxiom;
import org.semanticweb.owlapi.model.OWLDataFactory;
import org.semanticweb.owlapi.model.OWLDataProperty;
import org.semanticweb.owlapi.model.OWLDataPropertyAssertionAxiom;
import org.semanticweb.owlapi.model.OWLIndividual;
import org.semanticweb.owlapi.model.OWLObjectProperty;
import org.semanticweb.owlapi.model.OWLObjectPropertyAssertionAxiom;
import org.semanticweb.owlapi.model.OWLOntology;
import org.semanticweb.owlapi.model.OWLOntologyCreationException;
import org.semanticweb.owlapi.model.OWLOntologyManager;
import org.semanticweb.owlapi.model.OWLOntologyStorageException;
import org.semanticweb.owlapi.model.PrefixManager;
import org.semanticweb.owlapi.util.DefaultPrefixManager;
import org.semanticweb.owlapi.util.InferredOntologyGenerator;

import com.opencsv.CSVReader;
import com.opencsv.exceptions.CsvValidationException;

public class ontologia {

	//TODO completar paths a la ontologia
	static String pathOntologia_origen = "C:\\Users\\borja\\Desktop\\Terminar TFG V8\\Terminar TFG\\Python\\Carga individuos\\ontologia_vulnerabilidades.owl"; // Rellenar con el path al fichero .owl vacio de instancias
	static String pathOntologia_destino = "C:\\Users\\borja\\Desktop\\Terminar TFG V8\\Terminar TFG\\Python\\Carga individuos\\Java\\\\ontologia_vulnerabilidades_java.owl"; // En este path se almacena el .owl con los datos de individuos y el razonamiento


	@SuppressWarnings("resource")
	private static File copyFileOWL(File o, File d) throws IOException {

		if (d.exists()){
			d.delete();
		}
		d.createNewFile();

		FileChannel s = null;
		FileChannel ds = null;

		try {
			s = new RandomAccessFile(o, "rw").getChannel();
			ds = new RandomAccessFile(d, "rw").getChannel();

			long pos = 0;
			long count = s.size();

			s.transferTo(pos, count, ds);
		} finally {
			if (s != null){
				s.close();
			} if (ds != null){
				ds.close();
			}
		}

		return d;
	}


	// Equivalente a "poblar" en python
	public static void main (String [] args) throws IOException, OWLOntologyCreationException, CsvValidationException, OWLOntologyStorageException {

		// Inicia el contador
		long ti = System.currentTimeMillis();


		// Carga de las ontologias


		File f_origen = new File(pathOntologia_origen);
		File f_destino = new File(pathOntologia_destino);

		File f = copyFileOWL(f_origen,f_destino);

		OWLOntologyManager man = OWLManager.createOWLOntologyManager();
		OWLDataFactory df = man.getOWLDataFactory();

		OWLOntology o = man.loadOntologyFromOntologyDocument(f);
		String base = "http://www.semanticweb.org/borja/ontologies/2022/ontologia_vulnerabilidades";

		// Carga CSV empresas y paises

		//TODO - PATH A CSV EMPRESAS y PAISES
		String archCSV = "C:\\Users\\borja\\Desktop\\Terminar TFG V8\\Terminar TFG\\Python\\Carga individuos\\Prueba 9\\population_empresas_paises.csv";
		CSVReader csvReader = new CSVReader(new FileReader(archCSV));
		String[] fila = null;
		while((fila = csvReader.readNext()) != null) {

			String empresa = fila[0], pais = fila[1];

			if (!empresa.equals("Empresas") && !pais.equals("Paises")) {

				PrefixManager b = new DefaultPrefixManager(base + "#");

				OWLIndividual empresa_ind = df.getOWLNamedIndividual(IRI.create(base + "#" + empresa));
				OWLClassAssertionAxiom axioma0 = df.getOWLClassAssertionAxiom(df.getOWLClass(":Empresa_Afectada", b), empresa_ind);
				man.addAxiom(o, axioma0);

				OWLIndividual pais_ind = df.getOWLNamedIndividual(IRI.create(base + "#" + pais));
				OWLClassAssertionAxiom axioma1 = df.getOWLClassAssertionAxiom(df.getOWLClass(":Pais", b), pais_ind);
				man.addAxiom(o, axioma1);

				man.saveOntology(o);
			}
		}
		csvReader.close();

		// Carga CSV CVE y ATT

		// TODO - PATH A CSV INDIVIDUOS
		archCSV = "C:\\Users\\borja\\Desktop\\Terminar TFG V8\\Terminar TFG\\Python\\Carga individuos\\Prueba 9\\population_individuals.csv";
		csvReader = new CSVReader(new FileReader(archCSV));
		fila = null;
		while((fila = csvReader.readNext()) != null) {

			String id_cve = fila[0], 
					confidencialidad = fila[1], 
					integridad = fila[2],
					disponibilidad = fila[3],
					economico = fila[4],
					ideologico = fila[5],
					difamacion = fila[6],
					desafio_Intelectual = fila[7],
					destruccion = fila[8],
					secuestro = fila[9],
					obtencion = fila[10],
					ano_CVE = fila[11],
					identificador_CVE = fila[12],
					genera = fila[13],
					tipo_de_vulnerabilidad = fila[14],
					id_ATT = fila[15],
					ano_ATT = fila[16],
					identificador_ATT = fila[17],
					afectaAlPais = fila[18],
					afectaLaEmpresa = fila[19],
					capa_del_ataque = fila[20],
					tipo_de_producto_afectado = fila[21];


			if (id_cve.startsWith("CVE") && id_ATT.startsWith("ATT")) {
				PrefixManager b = new DefaultPrefixManager(base + "#");

				// ATTs
				OWLIndividual att_ind = df.getOWLNamedIndividual(IRI.create(base + "#" + id_ATT));
				OWLClassAssertionAxiom axioma0 = df.getOWLClassAssertionAxiom(df.getOWLClass(":Ataque", b), att_ind);
				man.addAxiom(o, axioma0);

				OWLDataProperty dproperty = df.getOWLDataProperty(":Ano", b);	
				OWLDataPropertyAssertionAxiom dAxiom = df.getOWLDataPropertyAssertionAxiom(dproperty, att_ind, Integer.valueOf(ano_ATT));
				man.addAxiom(o, dAxiom);

				dproperty = df.getOWLDataProperty(":Identificador", b);
				dAxiom = df.getOWLDataPropertyAssertionAxiom(dproperty, att_ind, Integer.valueOf(identificador_ATT));
				man.addAxiom(o, dAxiom);

				OWLObjectProperty op = df.getOWLObjectProperty(":afectaLaEmpresa", b);
				OWLObjectPropertyAssertionAxiom oAxiom = df.getOWLObjectPropertyAssertionAxiom(op, att_ind, df.getOWLNamedIndividual(IRI.create(base +"#"+afectaLaEmpresa)));
				man.addAxiom(o, oAxiom);

				op = df.getOWLObjectProperty(":atacaAlPais", b);
				oAxiom = df.getOWLObjectPropertyAssertionAxiom(op, att_ind, df.getOWLNamedIndividual(IRI.create(base +"#"+afectaAlPais)));
				man.addAxiom(o, oAxiom);

				axioma0 = df.getOWLClassAssertionAxiom(df.getOWLClass(":"+capa_del_ataque, b), att_ind);
				man.addAxiom(o, axioma0);

				axioma0 = df.getOWLClassAssertionAxiom(df.getOWLClass(":"+tipo_de_producto_afectado, b), att_ind);
				man.addAxiom(o, axioma0);

				//CVEs

				OWLIndividual cve_ind = df.getOWLNamedIndividual(IRI.create(base + "#" + id_cve));
				OWLClassAssertionAxiom axioma1 = df.getOWLClassAssertionAxiom(df.getOWLClass(":Vulnerabilidad", b), cve_ind);
				man.addAxiom(o, axioma1);

				OWLDataProperty dproperty1 = df.getOWLDataProperty(":Confidencialidad", b);	
				OWLDataPropertyAssertionAxiom dAxiom1 = df.getOWLDataPropertyAssertionAxiom(dproperty1, cve_ind, confidencialidad);
				man.addAxiom(o, dAxiom1);

				dproperty1 = df.getOWLDataProperty(":Integridad", b);
				dAxiom1 = df.getOWLDataPropertyAssertionAxiom(dproperty1, cve_ind, integridad);
				man.addAxiom(o, dAxiom1);

				dproperty1 = df.getOWLDataProperty(":Disponibilidad", b);
				dAxiom1 = df.getOWLDataPropertyAssertionAxiom(dproperty1, cve_ind, disponibilidad);
				man.addAxiom(o, dAxiom1);

				dproperty1 = df.getOWLDataProperty(":Economico", b);
				dAxiom1 = df.getOWLDataPropertyAssertionAxiom(dproperty1, cve_ind, economico);
				man.addAxiom(o, dAxiom1);

				dproperty1 = df.getOWLDataProperty(":Ideologico", b);
				dAxiom1 = df.getOWLDataPropertyAssertionAxiom(dproperty1, cve_ind, ideologico);
				man.addAxiom(o, dAxiom1);

				dproperty1 = df.getOWLDataProperty(":Difamacion", b);
				dAxiom1 = df.getOWLDataPropertyAssertionAxiom(dproperty1, cve_ind, difamacion);
				man.addAxiom(o, dAxiom1);

				dproperty1 = df.getOWLDataProperty(":Desafio_Intelectual", b);
				dAxiom1 = df.getOWLDataPropertyAssertionAxiom(dproperty1, cve_ind, desafio_Intelectual);
				man.addAxiom(o, dAxiom1);

				dproperty1 = df.getOWLDataProperty(":Destruccion", b);
				dAxiom1 = df.getOWLDataPropertyAssertionAxiom(dproperty1, cve_ind, destruccion);
				man.addAxiom(o, dAxiom1);

				dproperty1 = df.getOWLDataProperty(":Secuestro", b);
				dAxiom1 = df.getOWLDataPropertyAssertionAxiom(dproperty1, cve_ind, secuestro);
				man.addAxiom(o, dAxiom1);

				dproperty1 = df.getOWLDataProperty(":Obtencion", b);
				dAxiom1 = df.getOWLDataPropertyAssertionAxiom(dproperty1, cve_ind, obtencion);
				man.addAxiom(o, dAxiom1);

				dproperty1 = df.getOWLDataProperty(":Ano", b);
				dAxiom1 = df.getOWLDataPropertyAssertionAxiom(dproperty1, cve_ind, Integer.valueOf(ano_CVE));
				man.addAxiom(o, dAxiom1);

				dproperty1 = df.getOWLDataProperty(":Identificador", b);
				dAxiom1 = df.getOWLDataPropertyAssertionAxiom(dproperty1, cve_ind, Integer.valueOf(identificador_CVE));
				man.addAxiom(o, dAxiom1);

				OWLObjectProperty op1 = df.getOWLObjectProperty(":genera", b);
				OWLObjectPropertyAssertionAxiom oAxiom1 = df.getOWLObjectPropertyAssertionAxiom(op1, cve_ind, df.getOWLNamedIndividual(IRI.create(base +"#"+genera)));
				man.addAxiom(o, oAxiom1);

				axioma1 = df.getOWLClassAssertionAxiom(df.getOWLClass(":"+tipo_de_vulnerabilidad, b), cve_ind);
				man.addAxiom(o, axioma1);

				man.saveOntology(o);
			}
		}
		csvReader.close();

		// Ejecutamos el razonador

		OWLReasonerFactory reasonerFactory = new ReasonerFactory();
		OWLReasoner reasoner = reasonerFactory.createReasoner(o);

		reasoner.precomputeInferences();
		System.out.println(reasoner.isConsistent());
		System.out.println(reasoner.getReasonerName());

		InferredOntologyGenerator iog = new InferredOntologyGenerator(reasoner);//, gens);
		iog.fillOntology(df, o);

		man.saveOntology(o);

		// Ejecuta las reglas

		Model model = ModelFactory.createDefaultModel();
		// comprobar que funciona este path
		model.read(pathOntologia_destino);

		// 12 horas
		String query = "PREFIX o: <http://www.semanticweb.org/borja/ontologies/2022/ontologia_vulnerabilidades#>"
				+ "CONSTRUCT { ?cve a o:12_horas.}"
				+ "WHERE {{?cve a o:Muy_alta. ?cve a o:Code_Execution.} UNION "
				+ "{?cve a o:Muy_alta. ?cve a o:Memory_Corruption.} UNION"
				+ " {?cve a o:Muy_alta. ?cve a o:Overflow.} UNION"
				+ " {?cve a o:Alta. ?cve a o:Code_Execution.} UNION"
				+ " {?cve a o:Alta. ?cve a o:Memory_Corruption.} UNION {?cve a o:Alta. ?cve a o:Overflow.}}";

		Query q = QueryFactory.create(query) ;
		QueryExecution qexec = QueryExecutionFactory.create(q, model);
		Model results = qexec.execConstruct();
		model.add(results);
		qexec.close();

		// 24 horas	
		query = "PREFIX o: <http://www.semanticweb.org/borja/ontologies/2022/ontologia_vulnerabilidades#>"
				+ "     CONSTRUCT { ?cve a o:24_horas.}"
				+ "     WHERE  {{?cve a o:Muy_alta. ?cve a o:Gain_Information.} UNION "
				+ "         {?cve a o:Muy_alta. ?cve a o:Gain_Privileges.} UNION"
				+ "{?cve a o:Muy_alta. ?cve a o:XSS.} UNION"
				+ " {?cve a o:Alta. ?cve a o:Gain_Information.} UNION"
				+ "{?cve a o:Alta. ?cve a o:Gain_Privileges.} UNION"
				+ " {?cve a o:Alta. ?cve a o:XSS.} UNION"
				+ "{?cve a o:Normal. ?cve a o:Code_Execution.} UNION"
				+ " {?cve a o:Normal. ?cve a o:Memory_Corruption.} UNION"
				+ "{?cve a o:Normal. ?cve a o:Overflow.}}";

		q = QueryFactory.create(query) ;
		qexec = QueryExecutionFactory.create(q, model);
		results = qexec.execConstruct();
		model.add(results);
		qexec.close();


		// 3 dias
		query = "PREFIX o: <http://www.semanticweb.org/borja/ontologies/2022/ontologia_vulnerabilidades#>\n"
				+ "CONSTRUCT { ?cve a o:3_dias.}\n"
				+ "WHERE  {{?cve a o:Muy_alta. ?cve a o:DoS.} UNION \n"
				+ "{?cve a o:Muy_alta. ?cve a o:Http_Response_Splitting.} UNION\n"
				+ "{?cve a o:Muy_alta. ?cve a o:Sql_injection.} UNION\n"
				+ "{?cve a o:Alta. ?cve a o:DoS.} UNION\n"
				+ "{?cve a o:Alta. ?cve a o:Http_Response_Splitting.} UNION\n"
				+ "{?cve a o:Alta. ?cve a o:Sql_injection.} UNION\n"
				+ "{?cve a o:Normal. ?cve a o:Gain_Information.} UNION\n"
				+ "{?cve a o:Normal. ?cve a o:Gain_Privileges.} UNION\n"
				+ "{?cve a o:Normal. ?cve a o:XSS.} UNION\n"
				+ "{?cve a o:Baja. ?cve a o:Code_Execution.} UNION\n"
				+ "{?cve a o:Baja. ?cve a o:Memory_Corruption.} UNION\n"
				+ "{?cve a o:Baja. ?cve a o:Overflow.} UNION\n"
				+ "{?cve a o:Muy_baja. ?cve a o:Code_Execution.} UNION\n"
				+ "{?cve a o:Muy_baja. ?cve a o:Memory_Corruption.} UNION\n"
				+ "{?cve a o:Muy_baja. ?cve a o:Overflow.}}";

		q = QueryFactory.create(query) ;
		qexec = QueryExecutionFactory.create(q, model);
		results = qexec.execConstruct();
		model.add(results);
		qexec.close();


		// 15 dias
		query = "PREFIX o: <http://www.semanticweb.org/borja/ontologies/2022/ontologia_vulnerabilidades#>\n"
				+ "CONSTRUCT { ?cve a o:15_dias.}\n"
				+ "WHERE  {{?cve a o:Normal. ?cve a o:DoS.} UNION \n"
				+ "{?cve a o:Normal. ?cve a o:Http_Response_Splitting.} UNION\n"
				+ "{?cve a o:Normal. ?cve a o:Sql_injection.} UNION\n"
				+ "{?cve a o:Baja. ?cve a o:Gain_Information.} UNION\n"
				+ "{?cve a o:Baja. ?cve a o:Gain_Privileges.} UNION\n"
				+ "{?cve a o:Baja. ?cve a o:XSS.} UNION\n"
				+ "{?cve a o:Muy_baja. ?cve a o:Gain_Information.} UNION\n"
				+ "{?cve a o:Muy_baja. ?cve a o:Gain_Privileges.} UNION\n"
				+ "{?cve a o:Muy_baja. ?cve a o:XSS.}}";

		q = QueryFactory.create(query) ;
		qexec = QueryExecutionFactory.create(q, model);
		results = qexec.execConstruct();
		model.add(results);
		qexec.close();


		// 30 dias
		query = "PREFIX o: <http://www.semanticweb.org/borja/ontologies/2022/ontologia_vulnerabilidades#>\n"
				+ "CONSTRUCT { ?cve a o:30_dias.}\n"
				+ "WHERE  {{?cve a o:Baja. ?cve a o:DoS.} UNION \n"
				+ "{?cve a o:Baja. ?cve a o:Http_Response_Splitting.} UNION\n"
				+ "{?cve a o:Baja. ?cve a o:Sql_injection.} UNION\n"
				+ "{?cve a o:Muy_baja. ?cve a o:DoS.} UNION\n"
				+ "{?cve a o:Muy_baja. ?cve a o:Http_Response_Splitting.} UNION\n"
				+ "{?cve a o:Muy_baja. ?cve a o:Sql_injection.}}";

		q = QueryFactory.create(query) ;
		qexec = QueryExecutionFactory.create(q, model);
		results = qexec.execConstruct();
		model.add(results);
		qexec.close();
		//TODO - COMPROBAR QUE FUNCIONA EL PATH
		FileOutputStream oFile = new FileOutputStream(pathOntologia_destino, false);
		model.write(oFile);



		long tf = System.currentTimeMillis();
		System.out.println("Tiempo (ms): ");
		System.out.println(tf-ti);
	}
}
