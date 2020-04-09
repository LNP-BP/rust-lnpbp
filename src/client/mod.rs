
pub trait GraphIter {

}

pub trait Graph {
    type Item: GraphIter;

    fn get_roots(&self) -> Vec<Self::Item>;
}
